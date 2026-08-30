package com.zafrida.ui.python;

import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.openapi.application.ReadAction;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.module.Module;
import com.intellij.openapi.module.ModuleManager;
import com.intellij.openapi.progress.ProcessCanceledException;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.projectRoots.ProjectJdkTable;
import com.intellij.openapi.projectRoots.Sdk;
import com.intellij.openapi.roots.ModuleRootManager;
import com.intellij.openapi.roots.ProjectRootManager;
import com.intellij.openapi.util.SystemInfoRt;
import com.zafrida.ui.fridaproject.ZaFridaProjectManager;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class ProjectPythonEnvResolver {

    private static final Logger LOG = Logger.getInstance(ProjectPythonEnvResolver.class);

    private static final List<String> UNIX_INTERPRETER_CANDIDATES = List.of(
            "bin/python",
            "bin/python3",
            "python",
            "python3"
    );
    private static final List<String> WINDOWS_INTERPRETER_CANDIDATES = List.of(
            "Scripts/python.exe",
            "python.exe",
            "bin/python.exe",
            "Scripts/python3.exe"
    );

    private ProjectPythonEnvResolver() {
    }

    /**
     * ZAFrida 项目显式配置优先；留空时读取 IDE Project/Module SDK。
     * 显式路径无效时抛错，禁止静默切到另一个 Frida 版本。
     */
    public static @Nullable PythonEnvInfo resolve(@NotNull Project project) {
        if (project.isDisposed()) {
            return null;
        }

        String configuredPath = readZaFridaProjectOverride(project);
        if (ZaStrUtil.isNotBlank(configuredPath)) {
            return resolveConfiguredPath(configuredPath);
        }
        return resolveIdeProject(project);
    }

    /** 支持解释器文件，或 venv/virtualenv、Conda、uv、Poetry、Pipenv、Hatch 等本地环境根目录。 */
    public static @NotNull PythonEnvInfo resolveConfiguredPath(@NotNull String configuredPath) {
        String normalizedInput = stripMatchingQuotes(configuredPath.trim());
        if (normalizedInput.isEmpty()) {
            throw new PythonEnvResolutionException("Python environment path is empty");
        }
        if (normalizedInput.contains("://")) {
            throw new PythonEnvResolutionException(
                    "Remote Python interpreters are not supported for local Frida processes: " + normalizedInput
            );
        }

        Path selectedPath;
        try {
            selectedPath = Paths.get(expandUserHome(normalizedInput));
        } catch (InvalidPathException e) {
            throw new PythonEnvResolutionException("Invalid Python environment path: " + normalizedInput, e);
        }
        if (!selectedPath.isAbsolute()) {
            throw new PythonEnvResolutionException(
                    "Python environment path must be absolute (or start with ~): " + normalizedInput
            );
        }
        selectedPath = selectedPath.normalize();

        Path interpreter = locateInterpreter(selectedPath);
        return buildFromPythonHome(interpreter, PythonEnvInfo.Source.ZAFRIDA_PROJECT);
    }

    /** 返回 PyCharm 当前项目、Module 及全局 SDK 表中的本地 Python 解释器路径。 */
    public static @NotNull List<String> listIdeInterpreterPaths(@NotNull Project project) {
        if (project.isDisposed()) {
            return List.of();
        }
        try {
            return ReadAction.compute(() -> {
                LinkedHashSet<String> paths = new LinkedHashSet<>();
                addSdkHome(paths, ProjectRootManager.getInstance(project).getProjectSdk());
                for (Module module : ModuleManager.getInstance(project).getModules()) {
                    addSdkHome(paths, ModuleRootManager.getInstance(module).getSdk());
                }
                for (Sdk sdk : ProjectJdkTable.getInstance().getAllJdks()) {
                    addSdkHome(paths, sdk);
                }
                return new ArrayList<>(paths);
            });
        } catch (ProcessCanceledException e) {
            throw e;
        } catch (RuntimeException e) {
            LOG.warn("List IDE Python interpreters failed", e);
            return List.of();
        }
    }

    public static @Nullable PythonEnvInfo resolveIdeProject(@NotNull Project project) {
        if (project.isDisposed()) {
            return null;
        }
        try {
            Sdk sdk = ReadAction.compute(() -> findPythonSdk(project));
            if (sdk == null || ZaStrUtil.isBlank(sdk.getHomePath())) {
                return null;
            }

            String homePath = sdk.getHomePath();
            if (homePath.contains("://")) {
                LOG.info(String.format("Skip non-local Python SDK for local Frida process: %s", homePath));
                return null;
            }

            Path interpreter = Paths.get(homePath).toAbsolutePath().normalize();
            if (!Files.isRegularFile(interpreter)) {
                LOG.warn(String.format("IDE Python interpreter does not exist: %s", interpreter));
                return null;
            }
            return buildFromPythonHome(interpreter, PythonEnvInfo.Source.IDE_PROJECT);
        } catch (ProcessCanceledException e) {
            throw e;
        } catch (InvalidPathException e) {
            LOG.warn("Invalid IDE Python interpreter path", e);
            return null;
        } catch (RuntimeException e) {
            LOG.warn("Resolve IDE Python environment failed", e);
            return null;
        }
    }

    private static @NotNull String readZaFridaProjectOverride(@NotNull Project project) {
        ZaFridaProjectManager manager = project.getService(ZaFridaProjectManager.class);
        if (manager == null) {
            return "";
        }
        return manager.getActivePythonEnvironmentPath();
    }

    private static @Nullable Sdk findPythonSdk(@NotNull Project project) {
        Sdk projectSdk = ProjectRootManager.getInstance(project).getProjectSdk();
        if (looksLikePythonSdk(projectSdk)) {
            return projectSdk;
        }

        for (Module module : ModuleManager.getInstance(project).getModules()) {
            Sdk moduleSdk = ModuleRootManager.getInstance(module).getSdk();
            if (looksLikePythonSdk(moduleSdk)) {
                return moduleSdk;
            }
        }
        return null;
    }

    private static boolean looksLikePythonSdk(@Nullable Sdk sdk) {
        if (sdk == null || ZaStrUtil.isBlank(sdk.getHomePath())) {
            return false;
        }

        String typeName = sdk.getSdkType().getName();
        if (ZaStrUtil.isNotBlank(typeName) && typeName.toLowerCase(Locale.ROOT).contains("python")) {
            return true;
        }

        try {
            Path home = Paths.get(sdk.getHomePath());
            Path fileName = home.getFileName();
            if (fileName == null) {
                return false;
            }
            String lowerName = fileName.toString().toLowerCase(Locale.ROOT);
            return lowerName.startsWith("python") || lowerName.startsWith("pypy");
        } catch (InvalidPathException e) {
            return false;
        }
    }

    private static void addSdkHome(@NotNull Set<String> paths, @Nullable Sdk sdk) {
        if (!looksLikePythonSdk(sdk)) {
            return;
        }
        String homePath = sdk.getHomePath();
        if (ZaStrUtil.isBlank(homePath) || homePath.contains("://")) {
            return;
        }
        try {
            Path path = Paths.get(homePath).toAbsolutePath().normalize();
            if (Files.isRegularFile(path)) {
                paths.add(path.toString());
            }
        } catch (InvalidPathException e) {
            LOG.debug(String.format("Ignore invalid Python SDK path: %s", homePath), e);
        }
    }

    private static @NotNull Path locateInterpreter(@NotNull Path selectedPath) {
        if (Files.isRegularFile(selectedPath)) {
            return selectedPath;
        }
        if (!Files.isDirectory(selectedPath)) {
            throw new PythonEnvResolutionException(
                    "Python interpreter or environment directory does not exist: " + selectedPath
            );
        }

        List<String> candidates;
        if (SystemInfoRt.isWindows) {
            candidates = WINDOWS_INTERPRETER_CANDIDATES;
        } else {
            candidates = UNIX_INTERPRETER_CANDIDATES;
        }
        for (String candidate : candidates) {
            Path interpreter = selectedPath.resolve(candidate);
            if (Files.isRegularFile(interpreter)) {
                return interpreter.toAbsolutePath().normalize();
            }
        }

        throw new PythonEnvResolutionException(
                "No Python interpreter found in environment directory: " + selectedPath
        );
    }

    private static @NotNull PythonEnvInfo buildFromPythonHome(@NotNull Path pythonHome,
                                                               @NotNull PythonEnvInfo.Source source) {
        Path absolutePythonHome = pythonHome.toAbsolutePath().normalize();
        Path pythonDir = absolutePythonHome.getParent();
        Path envRoot = inferEnvironmentRoot(pythonDir);
        Set<String> toolDirs = new LinkedHashSet<>();
        Set<String> pathEntries = new LinkedHashSet<>();

        if (SystemInfoRt.isWindows) {
            addIfDirectory(toolDirs, envRoot.resolve("Scripts"));
            addIfDirectory(toolDirs, envRoot);
            addIfDirectory(toolDirs, envRoot.resolve("bin"));

            addIfDirectory(pathEntries, envRoot.resolve("Scripts"));
            addIfDirectory(pathEntries, envRoot);
            addIfDirectory(pathEntries, envRoot.resolve("bin"));

            // Conda on Windows loads native dependencies from these directories.
            addIfDirectory(pathEntries, envRoot.resolve("Library").resolve("bin"));
            addIfDirectory(pathEntries, envRoot.resolve("Library").resolve("usr").resolve("bin"));
            addIfDirectory(pathEntries, envRoot.resolve("Library").resolve("mingw-w64").resolve("bin"));
        } else {
            if (pythonDir != null) {
                addIfDirectory(toolDirs, pythonDir);
                addIfDirectory(pathEntries, pythonDir);
            }
            addIfDirectory(toolDirs, envRoot.resolve("bin"));
            addIfDirectory(pathEntries, envRoot.resolve("bin"));
        }

        return new PythonEnvInfo(
                absolutePythonHome.toString(),
                envRoot.toAbsolutePath().normalize().toString(),
                new ArrayList<>(toolDirs),
                new ArrayList<>(pathEntries),
                source
        );
    }

    private static @NotNull Path inferEnvironmentRoot(@Nullable Path pythonDir) {
        if (pythonDir == null) {
            throw new PythonEnvResolutionException("Python interpreter has no parent directory");
        }
        Path fileName = pythonDir.getFileName();
        if (fileName == null) {
            return pythonDir;
        }
        String directoryName = fileName.toString();
        if ("bin".equals(directoryName) || "scripts".equalsIgnoreCase(directoryName)) {
            Path parent = pythonDir.getParent();
            if (parent != null) {
                return parent;
            }
        }
        return pythonDir;
    }

    private static void addIfDirectory(@NotNull Set<String> output, @NotNull Path path) {
        if (Files.isDirectory(path)) {
            output.add(path.toAbsolutePath().normalize().toString());
        }
    }

    public static void applyToCommandLine(@NotNull GeneralCommandLine commandLine,
                                          @NotNull PythonEnvInfo environment) {
        String pathKey = detectPathKey(commandLine);
        String oldPath = readEnvironmentVariable(commandLine, pathKey);
        commandLine.getEnvironment().put(pathKey, prependPath(environment.getPathEntries(), oldPath));
    }

    public static @Nullable String findTool(@NotNull PythonEnvInfo environment, @NotNull String baseName) {
        List<String> names = candidateToolNames(baseName);
        for (String directory : environment.getToolDirs()) {
            Path toolDirectory;
            try {
                toolDirectory = Paths.get(directory);
            } catch (InvalidPathException e) {
                continue;
            }

            for (String name : names) {
                Path candidate = toolDirectory.resolve(name);
                if (Files.isRegularFile(candidate)) {
                    return candidate.toAbsolutePath().normalize().toString();
                }
            }
        }
        return null;
    }

    private static @NotNull List<String> candidateToolNames(@NotNull String baseName) {
        List<String> names = new ArrayList<>();
        names.add(baseName);
        if (!SystemInfoRt.isWindows) {
            return names;
        }

        String lowerName = baseName.toLowerCase(Locale.ROOT);
        if (!lowerName.endsWith(".exe")) {
            names.add(String.format("%s.exe", baseName));
        }
        if (!lowerName.endsWith(".cmd")) {
            names.add(String.format("%s.cmd", baseName));
        }
        if (!lowerName.endsWith(".bat")) {
            names.add(String.format("%s.bat", baseName));
        }
        return names;
    }

    private static @NotNull String detectPathKey(@NotNull GeneralCommandLine commandLine) {
        if (commandLine.getEnvironment().containsKey("Path")) {
            return "Path";
        }
        if (commandLine.getEnvironment().containsKey("PATH")) {
            return "PATH";
        }
        if (System.getenv("Path") != null) {
            return "Path";
        }
        return "PATH";
    }

    private static @Nullable String readEnvironmentVariable(@NotNull GeneralCommandLine commandLine,
                                                             @NotNull String key) {
        String value = commandLine.getEnvironment().get(key);
        if (value != null) {
            return value;
        }
        value = System.getenv(key);
        if (value != null) {
            return value;
        }
        if ("Path".equals(key)) {
            return System.getenv("PATH");
        }
        return System.getenv("Path");
    }

    private static @NotNull String prependPath(@NotNull List<String> entries, @Nullable String original) {
        LinkedHashSet<String> combined = new LinkedHashSet<>();
        for (String entry : entries) {
            if (ZaStrUtil.isNotBlank(entry)) {
                combined.add(entry);
            }
        }
        if (ZaStrUtil.isNotBlank(original)) {
            String[] originalEntries = original.split(Pattern.quote(File.pathSeparator));
            for (String entry : originalEntries) {
                if (ZaStrUtil.isNotBlank(entry)) {
                    combined.add(entry);
                }
            }
        }
        return String.join(File.pathSeparator, combined);
    }

    private static @NotNull String expandUserHome(@NotNull String path) {
        if (!"~".equals(path) && !path.startsWith("~/") && !path.startsWith("~\\")) {
            return path;
        }
        String userHome = System.getProperty("user.home");
        if (ZaStrUtil.isBlank(userHome)) {
            return path;
        }
        if (path.length() == 1) {
            return userHome;
        }
        return Paths.get(userHome).resolve(path.substring(2)).toString();
    }

    private static @NotNull String stripMatchingQuotes(@NotNull String value) {
        if (value.length() < 2) {
            return value;
        }
        char first = value.charAt(0);
        char last = value.charAt(value.length() - 1);
        if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
            return value.substring(1, value.length() - 1).trim();
        }
        return value;
    }
}
