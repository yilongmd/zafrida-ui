package com.zafrida.ui.session;

import com.intellij.execution.process.ProcessHandler;
import org.jetbrains.annotations.NotNull;

public final class RunningSession {

    private final @NotNull ProcessHandler processHandler;
    private final @NotNull String logFilePath;
    private final @NotNull String commandLine;
    private final long startedAtEpochMillis;

    public RunningSession(@NotNull ProcessHandler processHandler,
                          @NotNull String logFilePath,
                          @NotNull String commandLine,
                          long startedAtEpochMillis) {
        this.processHandler = processHandler;
        this.logFilePath = logFilePath;
        this.commandLine = commandLine;
        this.startedAtEpochMillis = startedAtEpochMillis;
    }

    public @NotNull ProcessHandler getProcessHandler() {
        return processHandler;
    }

    public @NotNull String getLogFilePath() {
        return logFilePath;
    }

    public @NotNull String getCommandLine() {
        return commandLine;
    }

    public long getStartedAtEpochMillis() {
        return startedAtEpochMillis;
    }
}
