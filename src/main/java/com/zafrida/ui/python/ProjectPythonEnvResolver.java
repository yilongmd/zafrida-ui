package com.zafrida.ui.python;

import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.projectRoots.Sdk;
import com.intellij.openapi.roots.ProjectRootManager;
import com.intellij.openapi.util.SystemInfoRt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import com.intellij.openapi.module.Module;
import com.intellij.openapi.module.ModuleManager;
import com.intellij.openapi.roots.ModuleRootManager;


/**
 * [核心组件] Python 环境解析与注入器。
 * <p>
 * <strong>设计目的：</strong>
 * 解决 IntelliJ 插件子进程无法继承 PyCharm Terminal 激活的 venv/conda 环境的问题。
 * <p>
 * <strong>工作流程：</strong>
 * 1. 扫描 Project 或 Module 关联的 Python SDK。
 * 2. 识别 SDK 类型（System, Venv, Conda）并定位 bin/Scripts 目录。
 * 3. 生成 {@link PythonEnvInfo}，用于在 {@link com.zafrida.ui.frida.FridaCliService} 中修补 PATH 环境变量。
 *
 * @see com.zafrida.ui.frida.FridaCliService
 */
public final class ProjectPythonEnvResolver {

    private static final Logger LOG = Logger.getInstance(ProjectPythonEnvResolver.class);

    private ProjectPythonEnvResolver() {
    }

    /**
     * 尝试解析当前 Project 关联的 Python 环境信息。
     * <p>
     * 如果未找到合适的 Python SDK，或解析过程中发生错误，则返回 null。
     *
     * @param project 当前 IDE Project
     * @return 解析到的 PythonEnvInfo，或 null 如果未找到或解析失败
     */
    public static @Nullable PythonEnvInfo resolve(@NotNull Project project) {
        try {
            Sdk sdk = findPythonSdk(project);
            if (sdk == null) return null;

            String homePath = sdk.getHomePath();
            if (homePath == null || homePath.trim().isEmpty()) return null;

            // Some remote SDKs provide non-local paths (ssh://, docker://, etc.).
            // 某些远程 SDK 会返回非本地路径（如 ssh://、docker:// 等）。
            // We only support local filesystem paths here.
            // 此处仅支持本地文件系统路径。
            if (homePath.contains("://")) {
                LOG.info("Project python SDK looks remote, skip env patch: " + homePath);
                return null;
            }

            Path pythonHome = Paths.get(homePath);
            return buildFromPythonHome(pythonHome);
        } catch (InvalidPathException e) {
            LOG.warn("Invalid python home path", e);
            return null;
        } catch (Throwable t) {
            LOG.warn("Resolve python env failed", t);
            return null;
        }
    }

    /**
     * In PyCharm, the Python interpreter is often stored as Module SDK rather than Project SDK.
     * 在 PyCharm 中，Python 解释器经常挂载在 Module SDK 而非 Project SDK。
     * So we try:
     * 因此按以下顺序尝试：
     * 1) Project SDK
     * 1) Project SDK（项目级）
     * 2) Each Module SDK
     * 2) 各 Module SDK
     */
    /**
     * 尝试在当前 Project 中查找关联的 Python SDK。
     * <p>
     * 优先检查 Project SDK，然后遍历所有 Module 的 SDK。
     *
     * @param project 当前 IDE Project
     * @return 找到的 Python Sdk，或 null 如果未找到
     */
    private static @Nullable Sdk findPythonSdk(@NotNull Project project) {
        // 1) project sdk
        Sdk projectSdk = ProjectRootManager.getInstance(project).getProjectSdk();
        if (looksLikePythonSdk(projectSdk)) {
            return projectSdk;
        }

        // 2) module sdk
        Module[] modules = ModuleManager.getInstance(project).getModules();
        for (Module m : modules) {
            Sdk moduleSdk = ModuleRootManager.getInstance(m).getSdk();
            if (looksLikePythonSdk(moduleSdk)) {
                return moduleSdk;
            }
        }

        // fallback: if projectSdk exists but doesn't look like python (rare in PyCharm), still return it
        // 回退：若 Project SDK 存在但不太像 Python（PyCharm 里很少见），仍返回它
        if (projectSdk != null && projectSdk.getHomePath() != null && !projectSdk.getHomePath().isBlank()) {
            return projectSdk;
        }

        // fallback: first non-null module sdk
        // 回退：返回第一个非空的 Module SDK
        for (Module m : modules) {
            Sdk moduleSdk = ModuleRootManager.getInstance(m).getSdk();
            if (moduleSdk != null && moduleSdk.getHomePath() != null && !moduleSdk.getHomePath().isBlank()) {
                return moduleSdk;
            }
        }

        return null;
    }

    /**
     * 简单判断给定 SDK 是否可能是 Python SDK。
     *
     * @param sdk 待检查的 Sdk 实例
     * @return 如果看起来像 Python SDK 则返回 true，否则返回 false
     */
    private static boolean looksLikePythonSdk(@Nullable Sdk sdk) {
        if (sdk == null) return false;

        String home = sdk.getHomePath();
        if (home == null || home.isBlank()) return false;

        // Prefer SDK type name when available
        // 优先使用 SDK 类型名称进行判断
        try {
            String typeName = sdk.getSdkType().getName();
            if (typeName != null && typeName.toLowerCase(Locale.ROOT).contains("python")) {
                return true;
            }
        } catch (Throwable ignored) {
        }

        // Fallback: check executable file name
        // 回退：检查可执行文件名
        try {
            String fileName = Paths.get(home).getFileName().toString().toLowerCase(Locale.ROOT);
            return fileName.startsWith("python") || fileName.startsWith("pypy");
        } catch (Throwable ignored) {
            String lower = home.toLowerCase(Locale.ROOT);
            return lower.contains("/python") || lower.contains("\\python") || lower.contains("pypy");
        }
    }

    /**
     * 根据给定的 Python 可执行文件路径，构建对应的 PythonEnvInfo。
     * @param pythonHome NotNull Path 指向 python 可执行文件的完整路径
     * @return NotNull PythonEnvInfo 包含环境信息
     */
    private static @NotNull PythonEnvInfo buildFromPythonHome(@NotNull Path pythonHome) {
        boolean windows = SystemInfoRt.isWindows;
        Path pythonDir = pythonHome.getParent();

        Path envRoot = null;
        Set<String> toolDirs = new LinkedHashSet<>();
        Set<String> pathEntries = new LinkedHashSet<>();

        if (windows) {
            // venv: <env>\Scripts\python.exe
            // 示例：<env>\Scripts\python.exe
            // conda: <env>\python.exe (Scripts is sibling)
            // conda: <env>\python.exe（Scripts 同级）
            if (pythonDir != null && "scripts".equalsIgnoreCase(pythonDir.getFileName().toString())) {
                envRoot = pythonDir.getParent();
            } else {
                envRoot = pythonDir;
            }

            if (envRoot != null) {
                Path scripts = envRoot.resolve("Scripts");
                Path root = envRoot;
                Path libraryBin = envRoot.resolve("Library").resolve("bin");

                addIfDir(toolDirs, scripts);
                addIfDir(toolDirs, root);

                addIfDir(pathEntries, scripts);
                addIfDir(pathEntries, root);
                addIfDir(pathEntries, libraryBin);

                // Some conda setups also use <env>\bin
                // 某些 conda 环境也会使用 <env>\bin
                addIfDir(toolDirs, envRoot.resolve("bin"));
                addIfDir(pathEntries, envRoot.resolve("bin"));

                // Optional conda extra dirs (doesn't hurt if missing)
                // 可选的 conda 额外目录（缺失也无影响）
                addIfDir(pathEntries, envRoot.resolve("Library").resolve("usr").resolve("bin"));
                addIfDir(pathEntries, envRoot.resolve("Library").resolve("mingw-w64").resolve("bin"));
            }
        } else {
            // unix/mac: <env>/bin/python
            // 示例：<env>/bin/python
            if (pythonDir != null && "bin".equals(pythonDir.getFileName().toString())) {
                envRoot = pythonDir.getParent();
            } else {
                envRoot = pythonDir;
            }

            if (envRoot != null) {
                Path bin = envRoot.resolve("bin");
                addIfDir(toolDirs, bin);
                addIfDir(pathEntries, bin);
            }
        }

        String envRootStr = envRoot != null ? envRoot.toAbsolutePath().toString() : "";
        return new PythonEnvInfo(
                pythonHome.toAbsolutePath().toString(),
                envRootStr,
                new ArrayList<>(toolDirs),
                new ArrayList<>(pathEntries)
        );
    }

    /**
     * 如果路径是目录，则将其绝对路径添加到集合中。
     * @param out
     * @param p
     */
    private static void addIfDir(@NotNull Set<String> out, @NotNull Path p) {
        try {
            if (Files.isDirectory(p)) {
                out.add(p.toAbsolutePath().toString());
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * 将指定 Python 环境的信息注入到给定的命令行环境变量中，修补 PATH 变量。
     *
     * @param cmd 命令行对象，非空
     * @param env Python 环境信息，非空
     */
    public static void applyToCommandLine(@NotNull GeneralCommandLine cmd, @NotNull PythonEnvInfo env) {
        String pathKey = detectPathKey(cmd);
        String oldPath = readEnvVar(cmd, pathKey);
        String newPath = prependPath(env.getPathEntries(), oldPath);
        cmd.getEnvironment().put(pathKey, newPath);
    }

    /**
     * Try to locate a console script in the resolved python env.
     * 尝试在解析出的 Python 环境中定位控制台脚本。
     * Returns absolute path if found; otherwise null.
     * 如果找到则返回绝对路径，否则返回 null。
     */
    /**
     * 尝试在给定的 Python 环境中查找指定的工具脚本。
     *
     * @param env      Python 环境信息，非空
     * @param baseName 工具脚本的基本名称（不含扩展名），非空
     * @return 如果找到则返回工具脚本的绝对路径，否则返回 null
     */
    public static @Nullable String findTool(@NotNull PythonEnvInfo env, @NotNull String baseName) {
        List<String> names = candidateNames(baseName);
        for (String dir : env.getToolDirs()) {
            Path d;
            try {
                d = Paths.get(dir);
            } catch (InvalidPathException e) {
                continue;
            }

            for (String n : names) {
                Path p = d.resolve(n);
                try {
                    if (Files.isRegularFile(p)) {
                        return p.toAbsolutePath().toString();
                    }
                } catch (Throwable ignored) {
                }
            }
        }
        return null;
    }

    /**
     * 生成可能的工具脚本名称列表，考虑操作系统差异（如 Windows 的 .exe/.cmd/.bat 扩展名）。
     * @param baseName
     * @return NotNull List<String>
     */
    private static @NotNull List<String> candidateNames(@NotNull String baseName) {
        boolean windows = SystemInfoRt.isWindows;
        List<String> out = new ArrayList<>();
        out.add(baseName);

        if (windows) {
            String lower = baseName.toLowerCase(Locale.ROOT);
            if (!lower.endsWith(".exe")) out.add(baseName + ".exe");
            if (!lower.endsWith(".cmd")) out.add(baseName + ".cmd");
            if (!lower.endsWith(".bat")) out.add(baseName + ".bat");
        }
        return out;
    }

    /**
     * 检测命令行环境变量中 PATH 变量的正确键名（考虑大小写差异）。
     * @param cmd 命令行对象，非空
     * @return PATH 变量的键名，非空
     */
    private static @NotNull String detectPathKey(@NotNull GeneralCommandLine cmd) {
        // On Windows, the env var is typically "Path".
        // Windows 下 PATH 变量通常写作 "Path"。
        if (cmd.getEnvironment().containsKey("Path")) return "Path";
        if (cmd.getEnvironment().containsKey("PATH")) return "PATH";
        String sysPath = System.getenv("Path");
        if (sysPath != null) return "Path";
        return "PATH";
    }

    /**
     * 读取命令行环境变量中的指定键值，若不存在则回退到系统环境变量。
     * @param cmd 命令行对象，非空
     * @param key 环境变量键名，非空
     * @return 环境变量值，或 null 如果未找到
     */
    private static @Nullable String readEnvVar(@NotNull GeneralCommandLine cmd, @NotNull String key) {
        String v = cmd.getEnvironment().get(key);
        if (v != null) return v;
        // fallback to system env
        // 回退到系统环境变量
        String sys = System.getenv(key);
        if (sys != null) return sys;
        if (!"PATH".equals(key)) {
            // try alternative case
            // 尝试不同大小写
            String alt = "PATH".equalsIgnoreCase(key) ? "PATH" : "Path";
            return System.getenv(alt);
        }
        return null;
    }

    /**
     * 在原有 PATH 变量值前添加新的路径条目。
     *
     * @param prepend 需要添加的路径列表，非空
     * @param original 原有的 PATH 变量值，可能为 null
     * @return 新的 PATH 变量值，非空
     */
    private static @NotNull String prependPath(@NotNull List<String> prepend, @Nullable String original) {
        if (prepend.isEmpty()) {
            return original != null ? original : "";
        }

        // PATH 分隔符
        String sep = SystemInfoRt.isWindows ? ";" : ":";
        StringBuilder sb = new StringBuilder();

        for (String p : prepend) {
            if (p == null || p.isBlank()) continue;
            if (sb.length() > 0) sb.append(sep);
            sb.append(p);
        }

        if (original != null && !original.isBlank()) {
            if (sb.length() > 0) sb.append(sep);
            sb.append(original);
        }
        return sb.toString();
    }
}
