package com.zafrida.ui.session;

import com.intellij.execution.process.ProcessAdapter;
import com.intellij.execution.process.ProcessEvent;
import com.intellij.execution.process.ProcessHandler;
import com.intellij.execution.ui.ConsoleView;
import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.Key;
import com.zafrida.ui.frida.FridaCliService;
import com.zafrida.ui.frida.FridaRunConfig;
import com.zafrida.ui.logging.SessionLogWriter;
import com.zafrida.ui.logging.ZaFridaLogPaths;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.file.Path;
import java.util.function.Consumer;

public final class ZaFridaSessionService implements Disposable {

    private final @NotNull Project project;
    private final @NotNull FridaCliService fridaCliService;

    private @Nullable RunningSession current;
    private @Nullable SessionLogWriter logWriter;

    public ZaFridaSessionService(@NotNull Project project) {
        this.project = project;
        this.fridaCliService = ApplicationManager.getApplication().getService(FridaCliService.class);
    }

    public synchronized @NotNull RunningSession start(@NotNull FridaRunConfig config,
                                                      @NotNull ConsoleView consoleView,
                                                      @NotNull Consumer<String> info,
                                                      @NotNull Consumer<String> error) throws Exception {
        stop();

        String basePath = project.getBasePath();
        Path logFile = basePath != null ? ZaFridaLogPaths.newSessionLogFile(basePath) : null;
        String logPathStr = logFile != null ? logFile.toAbsolutePath().toString() : "(log disabled: project basePath is null)";

        SessionLogWriter writer = null;
        if (logFile != null) {
            writer = new SessionLogWriter(logFile);
        }
        this.logWriter = writer;

        // show command line
        String cmdLine = fridaCliService.buildRunCommandLine(project, config).getCommandLineString();
        info.accept("[ZAFrida] Command: " + cmdLine);

        ProcessHandler handler = fridaCliService.createRunProcessHandler(project, config);

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
                    finalWriter.append("\n[ZAFrida] Process terminated (exitCode=" + event.getExitCode() + ")\n");
                    finalWriter.close();
                }
            }
        });

        consoleView.attachToProcess(handler);
        handler.startNotify();

        RunningSession session = new RunningSession(handler, logPathStr);
        this.current = session;
        return session;
    }

    public synchronized void stop() {
        if (current != null) {
            ProcessHandler handler = current.getProcessHandler();
            if (!handler.isProcessTerminated()) {
                try {
                    handler.destroyProcess();
                } catch (Throwable ignored) {
                }
            }
            current = null;
        }

        if (logWriter != null) {
            try {
                logWriter.close();
            } catch (Throwable ignored) {
            }
            logWriter = null;
        }
    }

    public @NotNull ProcessAdapter createUiStateListener(@NotNull Runnable onTerminated) {
        return new ProcessAdapter() {
            @Override
            public void processTerminated(@NotNull ProcessEvent event) {
                onTerminated.run();
            }
        };
    }

    @Override
    public void dispose() {
        stop();
    }
}
