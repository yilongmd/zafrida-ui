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

public final class ZaFrida010EditorUtil {

    private static final String MAC_DEFAULT_APP = "/Applications/010 Editor.app";

    private ZaFrida010EditorUtil() {
    }

    public static void openFileIn010EditorAsync(@NotNull Project project, @NotNull String filePath) {
        ApplicationManager.getApplication().executeOnPooledThread(() -> openFileIn010Editor(project, filePath));
    }

    public static void openFileIn010Editor(@NotNull Project project, @NotNull String filePath) {
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

        EditorCommand cmd = resolve010EditorCommand(f.getAbsolutePath());
        if (cmd == null) {
            ApplicationManager.getApplication().invokeLater(() -> ZaFridaNotifier.warn(
                    project,
                    "ZAFrida",
                    "010 Editor not found. Please install it or set 010 Editor path in Settings | ZAFrida."
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
                    String.format("Failed to open 010 Editor (%s): %s", cmd.debugName, finalMsg)
            ));
        }
    }

    private static final class EditorCommand {
        private final @NotNull String debugName;
        private final @NotNull List<String> command;

        private EditorCommand(@NotNull String debugName, @NotNull List<String> command) {
            this.debugName = debugName;
            this.command = command;
        }
    }

    private static @Nullable EditorCommand resolve010EditorCommand(@NotNull String filePath) {
        ZaFridaSettingsState st = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class).getState();
        String configured = st.editor010Executable;
        if (ZaStrUtil.isNotBlank(configured)) {
            String exec = resolve010EditorExecutable(configured.trim());
            if (exec == null) {
                return null;
            }
            return build010EditorOpenCommand(exec, filePath, true);
        }

        String exec = autoDetect010EditorExecutable();
        if (exec == null) {
            return null;
        }
        return build010EditorOpenCommand(exec, filePath, false);
    }

    private static @Nullable EditorCommand build010EditorOpenCommand(@NotNull String exec,
                                                                     @NotNull String filePath,
                                                                     boolean fromSettings) {
        String debugName = "010 Editor (auto)";
        if (fromSettings) {
            debugName = "010 Editor (settings)";
        }

        if (SystemInfo.isMac && exec.endsWith(".app")) {
            List<String> cmd = new ArrayList<>();
            cmd.add("open");
            cmd.add("-a");
            cmd.add(exec);
            cmd.add(filePath);
            return new EditorCommand(debugName, cmd);
        }

        if (SystemInfo.isWindows) {
            String lower = exec.toLowerCase();
            if (lower.endsWith(".exe")) {
                List<String> cmd = new ArrayList<>();
                cmd.add(exec);
                cmd.add(filePath);
                return new EditorCommand(debugName, cmd);
            }

            List<String> cmd = new ArrayList<>();
            cmd.add("cmd.exe");
            cmd.add("/c");
            cmd.add(exec);
            cmd.add(filePath);
            return new EditorCommand(debugName, cmd);
        }

        List<String> cmd = new ArrayList<>();
        cmd.add(exec);
        cmd.add(filePath);
        return new EditorCommand(debugName, cmd);
    }

    private static @Nullable String resolve010EditorExecutable(@NotNull String raw) {
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
                if (!lower.endsWith(".exe")) {
                    inPath = findInPathExecutable(raw + ".exe");
                    if (inPath != null) {
                        return inPath.getAbsolutePath();
                    }
                }
                if (!lower.endsWith(".cmd")) {
                    inPath = findInPathExecutable(raw + ".cmd");
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

    private static @Nullable String autoDetect010EditorExecutable() {
        File inPath = null;
        if (SystemInfo.isWindows) {
            inPath = findInPathExecutable("010Editor.exe");
            if (inPath == null) {
                inPath = findInPathExecutable("010Editor");
            }
        } else {
            inPath = findInPathExecutable("010editor");
            if (inPath == null) {
                inPath = findInPathExecutable("010Editor");
            }
        }
        if (inPath != null) {
            return inPath.getAbsolutePath();
        }

        if (SystemInfo.isMac) {
            File app = new File(MAC_DEFAULT_APP);
            if (app.exists() && app.isDirectory()) {
                return app.getAbsolutePath();
            }
            return null;
        }

        if (SystemInfo.isWindows) {
            List<File> candidates = new ArrayList<>();
            String programFiles = System.getenv("ProgramFiles");
            if (ZaStrUtil.isNotBlank(programFiles)) {
                candidates.add(new File(programFiles, "010 Editor\\010Editor.exe"));
            }
            String programFilesX86 = System.getenv("ProgramFiles(x86)");
            if (ZaStrUtil.isNotBlank(programFilesX86)) {
                candidates.add(new File(programFilesX86, "010 Editor\\010Editor.exe"));
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
