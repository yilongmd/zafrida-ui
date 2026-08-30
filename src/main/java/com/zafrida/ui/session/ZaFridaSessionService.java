package com.zafrida.ui.session;

import com.intellij.execution.process.ProcessAdapter;
import com.intellij.execution.process.ProcessEvent;
import com.intellij.execution.process.ProcessHandler;
import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.execution.ui.ConsoleView;
import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.Key;
import com.zafrida.ui.frida.FridaCliService;
import com.zafrida.ui.frida.FridaRunConfig;
import com.zafrida.ui.logging.SessionLogWriter;
import com.zafrida.ui.logging.ZaFridaLogPaths;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Pattern;

/** 会话映射的读写全部由 synchronized 方法或显式 synchronized 块保护。 */
public final class ZaFridaSessionService implements Disposable {

    private static final Logger LOG = Logger.getInstance(ZaFridaSessionService.class);
    private static final Pattern SENSITIVE_ARGUMENT = Pattern.compile(
            "(?i)(--(?:token|password|secret|api-key)(?:=|\\s+))(\\\"[^\\\"]*\\\"|'[^']*'|\\S+)"
    );

    private final @NotNull Project project;
    private final @NotNull FridaCliService fridaCliService;

    private final EnumMap<ZaFridaSessionType, RunningSession> sessions = new EnumMap<>(ZaFridaSessionType.class);
    private final EnumMap<ZaFridaSessionType, SessionLogWriter> logWriters = new EnumMap<>(ZaFridaSessionType.class);
    private final Set<SessionLogWriter> activeLogWriters =
            Collections.newSetFromMap(new IdentityHashMap<>());

    public ZaFridaSessionService(@NotNull Project project) {
        this.project = project;
        this.fridaCliService = ApplicationManager.getApplication().getService(FridaCliService.class);
    }

    public synchronized @NotNull RunningSession start(@NotNull ZaFridaSessionType type,
                                                      @NotNull FridaRunConfig config,
                                                      @NotNull ConsoleView consoleView,
                                                      @NotNull Consumer<String> info,
                                                      @NotNull Consumer<String> error,
                                                      @Nullable String fridaProjectDir,
                                                      @Nullable String targetPackage) throws Exception {
        stop(type);

        GeneralCommandLine commandLine = fridaCliService.buildRunCommandLine(project, config);
        String safeCommandLine = redactSensitiveArguments(commandLine.getCommandLineString());
        info.accept(String.format("[ZAFrida] Command: %s", safeCommandLine));
        ProcessHandler handler = fridaCliService.createRunProcessHandler(commandLine);

        String basePath = project.getBasePath();
        String sessionTag = "run";
        if (type == ZaFridaSessionType.ATTACH) {
            sessionTag = "attach";
        }
        Path logFile = null;
        if (basePath != null) {
            logFile = ZaFridaLogPaths.newSessionLogFile(basePath, fridaProjectDir, targetPackage, sessionTag);
        }
        String logPathStr = "(log disabled: project basePath is null)";
        if (logFile != null) {
            logPathStr = logFile.toAbsolutePath().toString();
        }

        SessionLogWriter writer = null;
        if (logFile != null) {
            try {
                writer = new SessionLogWriter(logFile);
                writer.append(String.format("[ZAFrida] Session started: %s%n", Instant.now()));
                writer.append(String.format("[ZAFrida] Command: %s%n", safeCommandLine));
            } catch (Exception e) {
                LOG.warn(String.format("Create Frida session log writer failed: type=%s file=%s", type, logFile), e);
                error.accept(String.format("[ZAFrida] Log disabled: %s", e.getMessage()));
                logPathStr = String.format("(log disabled: %s)", e.getMessage());
            }
        }

        SessionLogWriter finalWriter = writer;
        handler.addProcessListener(new ProcessAdapter() {
            @Override
            public void onTextAvailable(@NotNull ProcessEvent event, @NotNull Key outputType) {
                if (finalWriter != null) {
                    finalWriter.append(event.getText());
                }
            }

            @Override
            public void processTerminated(@NotNull ProcessEvent event) {
                if (finalWriter != null) {
                    finalWriter.append(String.format("\n[ZAFrida] Process terminated (exitCode=%s)\n", event.getExitCode()));
                    finalWriter.close();
                }
                synchronized (ZaFridaSessionService.this) {
                    RunningSession current = sessions.get(type);
                    if (current != null && current.getProcessHandler() == handler) {
                        sessions.remove(type);
                    }
                    SessionLogWriter currentWriter = logWriters.get(type);
                    if (currentWriter == finalWriter) {
                        logWriters.remove(type);
                    }
                    activeLogWriters.remove(finalWriter);
                }
            }
        });

        RunningSession session = new RunningSession(
                handler,
                logPathStr,
                safeCommandLine,
                System.currentTimeMillis()
        );
        sessions.put(type, session);
        if (writer != null) {
            logWriters.put(type, writer);
            activeLogWriters.add(writer);
        }

        try {
            consoleView.attachToProcess(handler);
            handler.startNotify();
            return session;
        } catch (Throwable t) {
            sessions.remove(type);
            logWriters.remove(type);
            activeLogWriters.remove(writer);
            if (!handler.isProcessTerminated()) {
                handler.destroyProcess();
            }
            if (writer != null) {
                writer.close();
            }
            if (t instanceof Exception exception) {
                throw exception;
            }
            if (t instanceof Error errorValue) {
                throw errorValue;
            }
            throw new RuntimeException(t);
        }
    }

    public synchronized void stop(@NotNull ZaFridaSessionType type) {
        RunningSession session = sessions.remove(type);
        SessionLogWriter writer = logWriters.remove(type);
        if (session != null) {
            if (writer != null) {
                writer.append(String.format("%n[ZAFrida] Stop requested: %s%n", Instant.now()));
            }
            ProcessHandler handler = session.getProcessHandler();
            if (!handler.isProcessTerminated()) {
                try {
                    handler.destroyProcess();
                } catch (Throwable t) {
                    LOG.warn(String.format("Stop Frida process failed: type=%s", type), t);
                    closeTrackedWriter(writer, type);
                }
            }
            return;
        }
        closeTrackedWriter(writer, type);
    }

    public synchronized void stop() {
        for (ZaFridaSessionType type : ZaFridaSessionType.values()) {
            stop(type);
        }
    }

    public synchronized boolean isRunning(@NotNull ZaFridaSessionType type) {
        RunningSession session = sessions.get(type);
        return session != null && !session.getProcessHandler().isProcessTerminated();
    }

    public synchronized @Nullable RunningSession getRunningSession(@NotNull ZaFridaSessionType type) {
        RunningSession session = sessions.get(type);
        if (session == null || session.getProcessHandler().isProcessTerminated()) {
            return null;
        }
        return session;
    }

    private static @NotNull String redactSensitiveArguments(@NotNull String commandLine) {
        return SENSITIVE_ARGUMENT.matcher(commandLine).replaceAll("$1<redacted>");
    }

    public @NotNull ProcessAdapter createUiStateListener(@NotNull Runnable onTerminated) {
        return new ProcessAdapter() {
            @Override
            public void processTerminated(@NotNull ProcessEvent event) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    if (!project.isDisposed()) {
                        onTerminated.run();
                    }
                });
            }
        };
    }

    @Override
    public void dispose() {
        stop();
        List<SessionLogWriter> writers;
        synchronized (this) {
            writers = new ArrayList<>(activeLogWriters);
            activeLogWriters.clear();
            logWriters.clear();
        }
        for (SessionLogWriter writer : writers) {
            closeWriter(writer, null);
        }
    }

    private synchronized void closeTrackedWriter(@Nullable SessionLogWriter writer,
                                                 @NotNull ZaFridaSessionType type) {
        if (writer == null) {
            return;
        }
        activeLogWriters.remove(writer);
        closeWriter(writer, type);
    }

    private void closeWriter(@NotNull SessionLogWriter writer,
                             @Nullable ZaFridaSessionType type) {
        try {
            writer.close();
        } catch (Throwable t) {
            String context = "project disposal";
            if (type != null) {
                context = String.format("type=%s", type);
            }
            LOG.warn(String.format("Close Frida session log failed: %s", context), t);
        }
    }
}
