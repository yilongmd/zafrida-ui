package com.zafrida.ui.util;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.SystemInfo;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.settings.ZaFridaSettingsState;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public final class ZaFridaVsCodeUtil {

    private ZaFridaVsCodeUtil() {
    }

    public static void openFileInVsCodeAsync(@NotNull Project project, @NotNull String filePath) {
        ApplicationManager.getApplication().executeOnPooledThread(() -> openFileInVsCode(project, filePath));
    }

    public static void openPathInVsCodeAsync(@NotNull Project project, @NotNull String path) {
        ApplicationManager.getApplication().executeOnPooledThread(() -> openPathInVsCode(project, path));
    }

    public static void openFileInVsCode(@NotNull Project project, @NotNull String filePath) {
        if (ZaStrUtil.isBlank(filePath)) {
            ApplicationManager.getApplication().invokeLater(() ->
                    ZaFridaNotifier.warn(project, "ZAFrida", "No file path"));
            return;
        }

        File f = new File(filePath);
        if (!f.exists() || !f.isFile()) {
            ApplicationManager.getApplication().invokeLater(() ->
                    ZaFridaNotifier.warn(project, "ZAFrida", String.format("File not found: %s", f.getAbsolutePath())));
            return;
        }

        openPathInVsCode(project, f.getAbsolutePath());
    }

    public static void openPathInVsCode(@NotNull Project project, @NotNull String path) {
        if (ZaStrUtil.isBlank(path)) {
            ApplicationManager.getApplication().invokeLater(() ->
                    ZaFridaNotifier.warn(project, "ZAFrida", "No path"));
            return;
        }

        File f = new File(path);
        if (!f.exists()) {
            ApplicationManager.getApplication().invokeLater(() ->
                    ZaFridaNotifier.warn(project, "ZAFrida", String.format("Path not found: %s", f.getAbsolutePath())));
            return;
        }

        boolean isDir = f.isDirectory();
        VsCodeCommand cmd = resolveVsCodeCommand(f.getAbsolutePath(), isDir);
        if (cmd == null) {
            ApplicationManager.getApplication().invokeLater(() -> ZaFridaNotifier.warn(
                    project,
                    "ZAFrida",
                    "VS Code not found. Please install it or set VS Code path in Settings | ZAFrida."
            ));
            return;
        }

        try {
            new ProcessBuilder(cmd.command).start();
        } catch (Throwable t) {
            String msg = t.getMessage();
            if (ZaStrUtil.isBlank(msg)) {
                msg = t.getClass().getName();
            }
            String finalMsg = msg;
            ApplicationManager.getApplication().invokeLater(() -> ZaFridaNotifier.warn(
                    project,
                    "ZAFrida",
                    String.format("Failed to open VS Code (%s): %s", cmd.debugName, finalMsg)
            ));
        }
    }

    private static final class VsCodeCommand {
        private final @NotNull String debugName;
        private final @NotNull List<String> command;

        private VsCodeCommand(@NotNull String debugName, @NotNull List<String> command) {
            this.debugName = debugName;
            this.command = command;
        }
    }

    private static @Nullable VsCodeCommand resolveVsCodeCommand(@NotNull String path, boolean isDirectory) {
        ZaFridaSettingsState st = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class).getState();
        String configured = st.vscodeExecutable;
        if (ZaStrUtil.isNotBlank(configured)) {
            String exec = resolveVsCodeExecutable(configured.trim());
            if (exec == null) {
                return null;
            }
            return buildVsCodeOpenCommand(exec, path, isDirectory, true);
        }

        String exec = autoDetectVsCodeExecutable();
        if (exec == null) {
            return null;
        }
        return buildVsCodeOpenCommand(exec, path, isDirectory, false);
    }

    private static @Nullable VsCodeCommand buildVsCodeOpenCommand(@NotNull String exec,
                                                                  @NotNull String path,
                                                                  boolean isDirectory,
                                                                  boolean fromSettings) {
        String debugName = "VS Code (auto)";
        if (fromSettings) {
            debugName = "VS Code (settings)";
        }

        if (SystemInfo.isMac && exec.endsWith(".app")) {
            List<String> cmd = new ArrayList<>();
            cmd.add("open");
            cmd.add("-a");
            cmd.add(exec);
            cmd.add(path);
            return new VsCodeCommand(debugName, cmd);
        }

        if (SystemInfo.isWindows) {
            if (exec.toLowerCase().endsWith(".exe")) {
                List<String> cmd = new ArrayList<>();
                cmd.add(exec);
                if (!isDirectory) {
                    cmd.add("-g");
                }
                cmd.add(path);
                return new VsCodeCommand(debugName, cmd);
            }
            List<String> cmd = new ArrayList<>();
            cmd.add("cmd.exe");
            cmd.add("/c");
            cmd.add(exec);
            if (!isDirectory) {
                cmd.add("-g");
            }
            cmd.add(path);
            return new VsCodeCommand(debugName, cmd);
        }

        List<String> cmd = new ArrayList<>();
        cmd.add(exec);
        if (!isDirectory) {
            cmd.add("-g");
        }
        cmd.add(path);
        return new VsCodeCommand(debugName, cmd);
    }

    private static @Nullable String resolveVsCodeExecutable(@NotNull String raw) {
        if (raw.isEmpty()) {
            return null;
        }

        if (!hasPathSeparator(raw)) {
            File inPath = findInPathExecutable(raw);
            if (inPath != null) {
                return inPath.getAbsolutePath();
            }
            if (SystemInfo.isWindows) {
                String lower = raw.toLowerCase();
                if (!lower.endsWith(".cmd")) {
                    inPath = findInPathExecutable(raw + ".cmd");
                    if (inPath != null) {
                        return inPath.getAbsolutePath();
                    }
                }
                if (!lower.endsWith(".exe")) {
                    inPath = findInPathExecutable(raw + ".exe");
                    if (inPath != null) {
                        return inPath.getAbsolutePath();
                    }
                }
                if (!lower.endsWith(".bat")) {
                    inPath = findInPathExecutable(raw + ".bat");
                    if (inPath != null) {
                        return inPath.getAbsolutePath();
                    }
                }
            }
            return null;
        }

        File f = new File(raw);
        if (f.exists()) {
            return f.getAbsolutePath();
        }
        return null;
    }

    private static @Nullable String autoDetectVsCodeExecutable() {
        File inPath = null;
        if (SystemInfo.isWindows) {
            inPath = findInPathExecutable("code.cmd");
            if (inPath == null) {
                inPath = findInPathExecutable("code");
            }
        } else {
            inPath = findInPathExecutable("code");
        }
        if (inPath != null) {
            return inPath.getAbsolutePath();
        }

        if (SystemInfo.isMac) {
            File app = new File("/Applications/Visual Studio Code.app");
            if (app.exists() && app.isDirectory()) {
                return app.getAbsolutePath();
            }
            return null;
        }

        if (SystemInfo.isWindows) {
            List<File> candidates = new ArrayList<>();
            String localAppData = System.getenv("LOCALAPPDATA");
            if (ZaStrUtil.isNotBlank(localAppData)) {
                candidates.add(new File(localAppData, "Programs\\Microsoft VS Code\\Code.exe"));
            }
            String programFiles = System.getenv("ProgramFiles");
            if (ZaStrUtil.isNotBlank(programFiles)) {
                candidates.add(new File(programFiles, "Microsoft VS Code\\Code.exe"));
            }
            String programFilesX86 = System.getenv("ProgramFiles(x86)");
            if (ZaStrUtil.isNotBlank(programFilesX86)) {
                candidates.add(new File(programFilesX86, "Microsoft VS Code\\Code.exe"));
            }

            for (File f : candidates) {
                if (f.exists() && f.isFile()) {
                    return f.getAbsolutePath();
                }
            }
        }

        return null;
    }

    private static boolean hasPathSeparator(@NotNull String s) {
        return s.indexOf('/') >= 0 || s.indexOf('\\') >= 0;
    }

    private static @Nullable File findInPathExecutable(@NotNull String name) {
        String pathEnv = System.getenv("PATH");
        if (ZaStrUtil.isBlank(pathEnv)) {
            return null;
        }
        String[] parts = pathEnv.split(Pattern.quote(File.pathSeparator));
        for (String dir : parts) {
            if (ZaStrUtil.isBlank(dir)) {
                continue;
            }
            File f = new File(dir.trim(), name);
            if (f.exists() && f.isFile()) {
                return f;
            }
        }
        return null;
    }
}
