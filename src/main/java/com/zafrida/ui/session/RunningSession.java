package com.zafrida.ui.session;

import com.intellij.execution.process.ProcessHandler;
import org.jetbrains.annotations.NotNull;
/**
 * [数据模型] 活跃的 Frida 会话句柄。
 * <p>
 * <strong>生命周期：</strong>
 * 从用户点击 "Run" 开始，到点击 "Stop" 或进程终止结束。
 * <p>
 * <strong>持有资源：</strong>
 * 1. {@link ProcessHandler}: 用于发送信号 (如 destroyProcess) 控制子进程。
 * 2. {@code logFilePath}: 当前会话对应的日志文件路径，用于 UI 显示。
 */
public final class RunningSession {

    private final @NotNull ProcessHandler processHandler;
    private final @NotNull String logFilePath;

    public RunningSession(@NotNull ProcessHandler processHandler, @NotNull String logFilePath) {
        this.processHandler = processHandler;
        this.logFilePath = logFilePath;
    }

    public @NotNull ProcessHandler getProcessHandler() {
        return processHandler;
    }

    public @NotNull String getLogFilePath() {
        return logFilePath;
    }
}
