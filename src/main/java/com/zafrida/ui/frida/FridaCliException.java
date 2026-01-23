package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;

/**
 * [异常] Frida CLI 工具执行失败异常。
 * <p>
 * <strong>触发条件：</strong>
 * 当外部进程返回非零退出码 (Exit Code != 0) 时抛出。
 * <p>
 * <strong>包含信息：</strong>
 * 包含完整的命令行字符串、Stdout 和 Stderr，以便在 UI 层或日志中诊断
 * "为什么 frida 启动失败" (例如：设备未找到、Python 环境错误、权限不足等)。
 */
public final class FridaCliException extends RuntimeException {

    /** 命令行完整字符串 */
    private final @NotNull String commandLine;
    /** 退出码 */
    private final int exitCode;
    /** 标准输出 */
    private final @NotNull String stdout;
    /** 标准错误 */
    private final @NotNull String stderr;

    /**
     * 构造函数。
     * @param message 异常描述
     * @param commandLine 命令行字符串
     * @param exitCode 退出码
     * @param stdout 标准输出
     * @param stderr 标准错误
     */
    public FridaCliException(@NotNull String message,
                            @NotNull String commandLine,
                            int exitCode,
                            @NotNull String stdout,
                            @NotNull String stderr) {
        super(message);
        this.commandLine = commandLine;
        this.exitCode = exitCode;
        this.stdout = stdout;
        this.stderr = stderr;
    }

    /**
     * 获取命令行字符串。
     * @return 命令行字符串
     */
    public @NotNull String getCommandLine() {
        return commandLine;
    }

    /**
     * 获取退出码。
     * @return 退出码
     */
    public int getExitCode() {
        return exitCode;
    }

    /**
     * 获取标准输出。
     * @return 标准输出
     */
    public @NotNull String getStdout() {
        return stdout;
    }

    /**
     * 获取标准错误。
     * @return 标准错误
     */
    public @NotNull String getStderr() {
        return stderr;
    }
}
