package com.zafrida.ui.python;

import org.jetbrains.annotations.NotNull;

import java.util.List;

public final class PythonEnvInfo {

    public enum Source {
        IDE_PROJECT,
        ZAFRIDA_PROJECT
    }

    private final @NotNull String pythonHome;
    private final @NotNull String envRoot;
    private final @NotNull List<String> toolDirs;
    private final @NotNull List<String> pathEntries;
    private final @NotNull Source source;

    public PythonEnvInfo(@NotNull String pythonHome,
                         @NotNull String envRoot,
                         @NotNull List<String> toolDirs,
                         @NotNull List<String> pathEntries,
                         @NotNull Source source) {
        this.pythonHome = pythonHome;
        this.envRoot = envRoot;
        this.toolDirs = List.copyOf(toolDirs);
        this.pathEntries = List.copyOf(pathEntries);
        this.source = source;
    }

    public @NotNull String getPythonHome() {
        return pythonHome;
    }

    public @NotNull String getEnvRoot() {
        return envRoot;
    }

    public @NotNull List<String> getToolDirs() {
        return toolDirs;
    }

    public @NotNull List<String> getPathEntries() {
        return pathEntries;
    }

    public @NotNull Source getSource() {
        return source;
    }
}
