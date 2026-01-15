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

    private final @NotNull String commandLine;
    private final int exitCode;
    private final @NotNull String stdout;
    private final @NotNull String stderr;

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

    public @NotNull String getCommandLine() {
        return commandLine;
    }

    public int getExitCode() {
        return exitCode;
    }

    public @NotNull String getStdout() {
        return stdout;
    }

    public @NotNull String getStderr() {
        return stderr;
    }
}
