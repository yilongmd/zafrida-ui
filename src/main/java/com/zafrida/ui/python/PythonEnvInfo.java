package com.zafrida.ui.python;

import org.jetbrains.annotations.NotNull;

import java.util.Collections;
import java.util.List;

/**
 * [DTO] Python 解释器环境描述符。
 * <p>
 * <strong>用途：</strong>
 * 封装了从 IDE 项目中解析出的 Python 环境信息（Conda/Venv 根目录、bin 目录、PATH 条目）。
 * 用于确保插件调用的 {@code frida-tools} 与用户在 PyCharm 中配置的 Python 环境一致。
 */
public final class PythonEnvInfo {

    private final @NotNull String pythonHome;
    private final @NotNull String envRoot;
    private final @NotNull List<String> toolDirs;
    private final @NotNull List<String> pathEntries;

    public PythonEnvInfo(@NotNull String pythonHome,
                         @NotNull String envRoot,
                         @NotNull List<String> toolDirs,
                         @NotNull List<String> pathEntries) {
        this.pythonHome = pythonHome;
        this.envRoot = envRoot;
        this.toolDirs = Collections.unmodifiableList(toolDirs);
        this.pathEntries = Collections.unmodifiableList(pathEntries);
    }

    public @NotNull String getPythonHome() {
        return pythonHome;
    }

    public @NotNull String getEnvRoot() {
        return envRoot;
    }

    /**
     * Directories where console scripts are expected (bin / Scripts).
     */
    public @NotNull List<String> getToolDirs() {
        return toolDirs;
    }

    /**
     * Directories to prepend into PATH when spawning processes.
     */
    public @NotNull List<String> getPathEntries() {
        return pathEntries;
    }
}
