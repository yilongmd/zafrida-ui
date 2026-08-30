package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;

public final class FridaCliException extends RuntimeException {

    private final @NotNull String commandLine;
    private final int exitCode;
    private final @NotNull String stdout;
    private final @NotNull String stderr;
    private final boolean timedOut;

    public FridaCliException(@NotNull String message,
                            @NotNull String commandLine,
                            int exitCode,
                            @NotNull String stdout,
                            @NotNull String stderr) {
        this(message, commandLine, exitCode, stdout, stderr, false);
    }

    public FridaCliException(@NotNull String message,
                             @NotNull String commandLine,
                             int exitCode,
                             @NotNull String stdout,
                             @NotNull String stderr,
                             boolean timedOut) {
        super(message);
        this.commandLine = commandLine;
        this.exitCode = exitCode;
        this.stdout = stdout;
        this.stderr = stderr;
        this.timedOut = timedOut;
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

    public boolean isTimedOut() {
        return timedOut;
    }
}
