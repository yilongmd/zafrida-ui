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
 * Resolve the project's selected Python interpreter environment and apply it to a command line.
 *
 * <p>Why this is needed:
 * PyCharm's integrated terminal activates venv/conda and modifies PATH.
 * But plugin-spawned processes inherit the IDE process environment, not the terminal.
 * Therefore, running "frida-ls-devices" by name may fail even if it works in the terminal.
 *
 * <p>This class prepends the project's interpreter environment directories to PATH,
 * so frida-tools is resolved from the same env as the project interpreter.
 */
public final class ProjectPythonEnvResolver {

    private static final Logger LOG = Logger.getInstance(ProjectPythonEnvResolver.class);

    private ProjectPythonEnvResolver() {
    }

    public static @Nullable PythonEnvInfo resolve(@NotNull Project project) {
        try {
            Sdk sdk = findPythonSdk(project);
            if (sdk == null) return null;

            String homePath = sdk.getHomePath();
            if (homePath == null || homePath.trim().isEmpty()) return null;

            // Some remote SDKs provide non-local paths (ssh://, docker://, etc.).
            // We only support local filesystem paths here.
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
     * So we try:
     * 1) Project SDK
     * 2) Each Module SDK
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
        if (projectSdk != null && projectSdk.getHomePath() != null && !projectSdk.getHomePath().isBlank()) {
            return projectSdk;
        }

        // fallback: first non-null module sdk
        for (Module m : modules) {
            Sdk moduleSdk = ModuleRootManager.getInstance(m).getSdk();
            if (moduleSdk != null && moduleSdk.getHomePath() != null && !moduleSdk.getHomePath().isBlank()) {
                return moduleSdk;
            }
        }

        return null;
    }

    private static boolean looksLikePythonSdk(@Nullable Sdk sdk) {
        if (sdk == null) return false;

        String home = sdk.getHomePath();
        if (home == null || home.isBlank()) return false;

        // Prefer SDK type name when available
        try {
            String typeName = sdk.getSdkType().getName();
            if (typeName != null && typeName.toLowerCase(Locale.ROOT).contains("python")) {
                return true;
            }
        } catch (Throwable ignored) {
        }

        // Fallback: check executable file name
        try {
            String fileName = Paths.get(home).getFileName().toString().toLowerCase(Locale.ROOT);
            return fileName.startsWith("python") || fileName.startsWith("pypy");
        } catch (Throwable ignored) {
            String lower = home.toLowerCase(Locale.ROOT);
            return lower.contains("/python") || lower.contains("\\python") || lower.contains("pypy");
        }
    }


    private static @NotNull PythonEnvInfo buildFromPythonHome(@NotNull Path pythonHome) {
        boolean windows = SystemInfoRt.isWindows;
        Path pythonDir = pythonHome.getParent();

        Path envRoot = null;
        Set<String> toolDirs = new LinkedHashSet<>();
        Set<String> pathEntries = new LinkedHashSet<>();

        if (windows) {
            // venv: <env>\Scripts\python.exe
            // conda: <env>\python.exe (Scripts is sibling)
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
                addIfDir(toolDirs, envRoot.resolve("bin"));
                addIfDir(pathEntries, envRoot.resolve("bin"));

                // Optional conda extra dirs (doesn't hurt if missing)
                addIfDir(pathEntries, envRoot.resolve("Library").resolve("usr").resolve("bin"));
                addIfDir(pathEntries, envRoot.resolve("Library").resolve("mingw-w64").resolve("bin"));
            }
        } else {
            // unix/mac: <env>/bin/python
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

    private static void addIfDir(@NotNull Set<String> out, @NotNull Path p) {
        try {
            if (Files.isDirectory(p)) {
                out.add(p.toAbsolutePath().toString());
            }
        } catch (Throwable ignored) {
        }
    }

    public static void applyToCommandLine(@NotNull GeneralCommandLine cmd, @NotNull PythonEnvInfo env) {
        String pathKey = detectPathKey(cmd);
        String oldPath = readEnvVar(cmd, pathKey);
        String newPath = prependPath(env.getPathEntries(), oldPath);
        cmd.getEnvironment().put(pathKey, newPath);
    }

    /**
     * Try to locate a console script in the resolved python env.
     * Returns absolute path if found; otherwise null.
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

    private static @NotNull String detectPathKey(@NotNull GeneralCommandLine cmd) {
        // On Windows, the env var is typically "Path".
        if (cmd.getEnvironment().containsKey("Path")) return "Path";
        if (cmd.getEnvironment().containsKey("PATH")) return "PATH";
        String sysPath = System.getenv("Path");
        if (sysPath != null) return "Path";
        return "PATH";
    }

    private static @Nullable String readEnvVar(@NotNull GeneralCommandLine cmd, @NotNull String key) {
        String v = cmd.getEnvironment().get(key);
        if (v != null) return v;
        // fallback to system env
        String sys = System.getenv(key);
        if (sys != null) return sys;
        if (!"PATH".equals(key)) {
            // try alternative case
            String alt = "PATH".equalsIgnoreCase(key) ? "PATH" : "Path";
            return System.getenv(alt);
        }
        return null;
    }

    private static @NotNull String prependPath(@NotNull List<String> prepend, @Nullable String original) {
        if (prepend.isEmpty()) {
            return original != null ? original : "";
        }

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
