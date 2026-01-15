package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;

/**
 * [数据模型] 外部进程执行结果快照。
 * <p>
 * <strong>用途：</strong>
 * 封装一次 CLI 命令（如 <code>frida-ps</code>）执行后的完整状态，
 * 包含标准输出 (Stdout)、标准错误 (Stderr) 和退出码 (Exit Code)。
 * <p>
 * 用于 {@link com.zafrida.ui.frida.FridaCliService} 向由上层业务返回同步执行结果。
 */
public final class CapturedOut {

    public final @NotNull String stdout;
    public final @NotNull String stderr;
    public final int exitCode;

    public CapturedOut(@NotNull String stdout, @NotNull String stderr, int exitCode) {
        this.stdout = stdout;
        this.stderr = stderr;
        this.exitCode = exitCode;
    }
}
