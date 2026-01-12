package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;

/**
 * Captured stdout/stderr/exitCode from running a frida-tools CLI command.
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
