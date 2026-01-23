package com.zafrida.ui.session;

import com.intellij.execution.process.ProcessHandler;
import org.jetbrains.annotations.NotNull;
/**
 * [数据模型] 活跃的 Frida 会话句柄。
 * 这个也是核心之一, 因为它让我们可以在控制台中和 Frida 进程进行交互。
 * 例如, 可以通过控制台发送Process来查看当前Frida进程ID等信息。
 * <p>
 * <strong>生命周期：</strong>
 * 从用户点击 "Run" 开始，到点击 "Stop" 或进程终止结束。
 * <p>
 * <strong>持有资源：</strong>
 * 1. {@link ProcessHandler}: 用于发送信号 (如 destroyProcess) 控制子进程。
 * 2. {@code logFilePath}: 当前会话对应的日志文件路径，用于 UI 显示。
 */
public final class RunningSession {

    /** Frida 进程处理器 */
    private final @NotNull ProcessHandler processHandler;
    /** 会话日志文件路径 */
    private final @NotNull String logFilePath;

    /** 
     * 构造函数
     * @param processHandler Frida 进程处理器
     * @param logFilePath 会话日志文件路径

     */
    public RunningSession(@NotNull ProcessHandler processHandler, @NotNull String logFilePath) {
        this.processHandler = processHandler;
        this.logFilePath = logFilePath;
    }

    /**
     * 获取 Frida 进程处理器
     * @return NotNull ProcessHandler
     */
    public @NotNull ProcessHandler getProcessHandler() {
        return processHandler;
    }

    /**
     * 获取会话日志文件路径
     * @return NotNull 日志文件路径字符串
     */
    public @NotNull String getLogFilePath() {
        return logFilePath;
    }
}
