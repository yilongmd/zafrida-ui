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

    /** Python 可执行文件路径 */
    private final @NotNull String pythonHome;
    /** 环境根目录 */
    private final @NotNull String envRoot;
    /** 工具目录列表 */
    private final @NotNull List<String> toolDirs;
    /** PATH 前置条目列表 */
    private final @NotNull List<String> pathEntries;

    /**
     * 构造函数。
     * @param pythonHome Python 可执行文件路径
     * @param envRoot 环境根目录
     * @param toolDirs 工具目录列表
     * @param pathEntries PATH 条目列表
     */
    public PythonEnvInfo(@NotNull String pythonHome,
                         @NotNull String envRoot,
                         @NotNull List<String> toolDirs,
                         @NotNull List<String> pathEntries) {
        this.pythonHome = pythonHome;
        this.envRoot = envRoot;
        this.toolDirs = Collections.unmodifiableList(toolDirs);
        this.pathEntries = Collections.unmodifiableList(pathEntries);
    }

    /**
     * 获取 Python 可执行文件路径。
     * @return Python 路径
     */
    public @NotNull String getPythonHome() {
        return pythonHome;
    }

    /**
     * 获取环境根目录。
     * @return 环境根目录
     */
    public @NotNull String getEnvRoot() {
        return envRoot;
    }

    /**
     * Directories where console scripts are expected (bin / Scripts).
     * 控制台脚本所在目录（bin / Scripts）。
     */
    public @NotNull List<String> getToolDirs() {
        return toolDirs;
    }

    /**
     * Directories to prepend into PATH when spawning processes.
     * 进程启动时需要前置到 PATH 的目录。
     */
    public @NotNull List<String> getPathEntries() {
        return pathEntries;
    }
}
