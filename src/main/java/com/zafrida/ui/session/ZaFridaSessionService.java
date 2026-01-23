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
import java.util.EnumMap;
import java.util.function.Consumer;

/**
 * [会话管理] 负责 Frida 运行时的生命周期管理。
 * <p>
 * <strong>功能：</strong>
 * 1. 启动 Frida 进程并将输出流挂载到 {@link com.intellij.execution.ui.ConsoleView}。
 * 2. 维护 Run/Attach 两类 {@link RunningSession}。
 * 3. 负责日志持久化：将控制台输出实时写入 `zafrida-logs/` 目录。
 * <p>
 * <strong>线程安全：</strong> start/stop 方法是 synchronized 的。
 */
public final class ZaFridaSessionService implements Disposable {

    /** IDE 项目实例 */
    private final @NotNull Project project;
    /** Frida CLI 服务实例 */
    private final @NotNull FridaCliService fridaCliService;

    /** 会话类型到运行会话的映射 */
    private final EnumMap<ZaFridaSessionType, RunningSession> sessions = new EnumMap<>(ZaFridaSessionType.class);
    /** 会话类型到日志写入器的映射 */
    private final EnumMap<ZaFridaSessionType, SessionLogWriter> logWriters = new EnumMap<>(ZaFridaSessionType.class);

    /**
     * 构造函数。
     * @param project 当前 IDE 项目
     */
    public ZaFridaSessionService(@NotNull Project project) {
        this.project = project;
        this.fridaCliService = ApplicationManager.getApplication().getService(FridaCliService.class);
    }

    /**
     * 启动指定类型的会话。
     *
     * @param type 会话类型（Run/Attach）
     * @param config Frida 运行配置
     * @param consoleView 控制台视图
     * @param info 信息输出回调
     * @param error 错误输出回调
     * @param fridaProjectDir Frida 项目目录（可选）
     * @param targetPackage 目标包名（可选）
     * @return 已创建的运行会话
     */
    public synchronized @NotNull RunningSession start(@NotNull ZaFridaSessionType type,
                                                      @NotNull FridaRunConfig config,
                                                      @NotNull ConsoleView consoleView,
                                                      @NotNull Consumer<String> info,
                                                      @NotNull Consumer<String> error,
                                                      @Nullable String fridaProjectDir,
                                                      @Nullable String targetPackage) throws Exception {
        stop(type);

        String basePath = project.getBasePath();
        Path logFile = basePath != null ? ZaFridaLogPaths.newSessionLogFile(basePath, fridaProjectDir, targetPackage) : null;
        String logPathStr = logFile != null ? logFile.toAbsolutePath().toString() : "(log disabled: project basePath is null)";

        SessionLogWriter writer = null;
        if (logFile != null) {
            writer = new SessionLogWriter(logFile);
        }
        if (writer != null) {
            logWriters.put(type, writer);
        }

        // show command line
        // 显示命令行
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
                synchronized (ZaFridaSessionService.this) {
                    RunningSession current = sessions.get(type);
                    if (current != null && current.getProcessHandler() == handler) {
                        sessions.remove(type);
                    }
                    SessionLogWriter currentWriter = logWriters.get(type);
                    if (currentWriter == finalWriter) {
                        logWriters.remove(type);
                    }
                }
            }
        });

        consoleView.attachToProcess(handler);
        handler.startNotify();

        RunningSession session = new RunningSession(handler, logPathStr);
        sessions.put(type, session);
        return session;
    }

    /**
     * 停止指定类型的会话。
     * @param type 会话类型
     */
    public synchronized void stop(@NotNull ZaFridaSessionType type) {
        RunningSession session = sessions.remove(type);
        if (session != null) {
            ProcessHandler handler = session.getProcessHandler();
            if (!handler.isProcessTerminated()) {
                try {
                    handler.destroyProcess();
                } catch (Throwable ignored) {
                }
            }
        }

        SessionLogWriter writer = logWriters.remove(type);
        if (writer != null) {
            try {
                writer.close();
            } catch (Throwable ignored) {
            }
        }
    }

    /**
     * 停止所有会话。
     */
    public synchronized void stop() {
        for (ZaFridaSessionType type : ZaFridaSessionType.values()) {
            stop(type);
        }
    }

    /**
     * 判断指定类型的会话是否仍在运行。
     * @param type 会话类型
     * @return true 表示运行中
     */
    public synchronized boolean isRunning(@NotNull ZaFridaSessionType type) {
        RunningSession session = sessions.get(type);
        return session != null && !session.getProcessHandler().isProcessTerminated();
    }

    /**
     * 创建用于更新 UI 状态的进程监听器。
     * @param onTerminated 进程结束回调
     * @return ProcessAdapter 实例
     */
    public @NotNull ProcessAdapter createUiStateListener(@NotNull Runnable onTerminated) {
        return new ProcessAdapter() {
            @Override
            public void processTerminated(@NotNull ProcessEvent event) {
                onTerminated.run();
            }
        };
    }

    /**
     * 释放资源并停止所有会话。
     */
    @Override
    public void dispose() {
        stop();
    }
}
