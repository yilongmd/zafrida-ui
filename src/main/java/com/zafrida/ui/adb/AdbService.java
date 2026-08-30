package com.zafrida.ui.adb;

import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.execution.process.CapturingProcessHandler;
import com.intellij.execution.process.ProcessOutput;
import com.intellij.openapi.application.ApplicationManager;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public final class AdbService {

    private static final int DEFAULT_TIMEOUT_MS = 10_000;

    public void forwardTcp(int port,
                           @Nullable String deviceId,
                           @NotNull Consumer<String> info,
                           @NotNull Consumer<String> warn,
                           @NotNull Runnable onDone) {
        GeneralCommandLine cmd = buildForwardCommand(port, deviceId);
        info.accept(String.format("[ZAFrida] ADB forward: %s", cmd.getCommandLineString()));

        runAsync(cmd, result -> {
            if (result.exitCode != 0) {
                warn.accept(String.format("[ZAFrida] ADB forward failed (exitCode=%s)", result.exitCode));
            } else {
                info.accept(String.format("[ZAFrida] ADB forward ready on port %s", port));
            }
            if (ZaStrUtil.isNotBlank(result.stdout)) {
                info.accept(String.format("[ZAFrida] %s", result.stdout));
            }
            if (ZaStrUtil.isNotBlank(result.stderr)) {
                warn.accept(String.format("[ZAFrida] %s", result.stderr));
            }
            onDone.run();
        }, throwable -> {
            warn.accept(String.format("[ZAFrida] ADB forward failed: %s", throwable.getMessage()));
            onDone.run();
        });
    }

    public void forceStop(@NotNull String packageName,
                          @Nullable String deviceId,
                          @NotNull Consumer<String> info,
                          @NotNull Consumer<String> error) {
        GeneralCommandLine cmd = buildForceStopCommand(packageName, deviceId);
        info.accept(String.format("[ZAFrida] Force stop command: %s", cmd.getCommandLineString()));

        runAsync(cmd, result -> {
            if (result.exitCode == 0) {
                info.accept(String.format("[ZAFrida] Force stopped: %s", packageName));
                if (ZaStrUtil.isNotBlank(result.stdout)) {
                    info.accept(result.stdout);
                }
            } else {
                String detail = result.stdout;
                if (ZaStrUtil.isNotBlank(result.stderr)) {
                    detail = result.stderr;
                }
                if (ZaStrUtil.isBlank(detail)) {
                    detail = "unknown error";
                }
                error.accept(String.format("[ZAFrida] Force stop failed (exit=%s): %s", result.exitCode, detail));
            }
        }, throwable -> error.accept(String.format("[ZAFrida] Force stop failed: %s", throwable.getMessage())));
    }

    public void openApp(@NotNull String packageName,
                        @Nullable String deviceId,
                        @NotNull Consumer<String> info,
                        @NotNull Consumer<String> error) {
        GeneralCommandLine cmd = buildOpenAppCommand(packageName, deviceId);
        info.accept(String.format("[ZAFrida] Open app command: %s", cmd.getCommandLineString()));

        runAsync(cmd, result -> {
            if (result.exitCode == 0) {
                info.accept(String.format("[ZAFrida] Opened app: %s", packageName));
                if (ZaStrUtil.isNotBlank(result.stdout)) {
                    info.accept(result.stdout);
                }
            } else {
                String detail = result.stdout;
                if (ZaStrUtil.isNotBlank(result.stderr)) {
                    detail = result.stderr;
                }
                if (ZaStrUtil.isBlank(detail)) {
                    detail = "unknown error";
                }
                error.accept(String.format("[ZAFrida] Open app failed (exit=%s): %s", result.exitCode, detail));
            }
        }, throwable -> error.accept(String.format("[ZAFrida] Open app failed: %s", throwable.getMessage())));
    }

    private static @NotNull GeneralCommandLine buildForwardCommand(int port, @Nullable String deviceId) {
        String tcp = String.format("tcp:%s", port);
        List<String> args = baseAdbArgs(deviceId);
        args.add("forward");
        args.add(tcp);
        args.add(tcp);
        return new GeneralCommandLine(args)
                .withCharset(StandardCharsets.UTF_8);
    }

    public @NotNull GeneralCommandLine buildVersionCommandLine() {
        return new GeneralCommandLine("adb", "version")
                .withCharset(StandardCharsets.UTF_8);
    }

    private static @NotNull GeneralCommandLine buildForceStopCommand(@NotNull String packageName,
                                                                     @Nullable String deviceId) {
        List<String> args = baseAdbArgs(deviceId);
        args.add("shell");
        args.add("am");
        args.add("force-stop");
        args.add(packageName);
        return new GeneralCommandLine(args)
                .withCharset(StandardCharsets.UTF_8);
    }

    private static @NotNull GeneralCommandLine buildOpenAppCommand(@NotNull String packageName,
                                                                   @Nullable String deviceId) {
        List<String> args = baseAdbArgs(deviceId);
        args.add("shell");
        args.add("monkey");
        args.add("-p");
        args.add(packageName);
        args.add("-c");
        args.add("android.intent.category.LAUNCHER");
        args.add("1");
        return new GeneralCommandLine(args)
                .withCharset(StandardCharsets.UTF_8);
    }

    private static @NotNull List<String> baseAdbArgs(@Nullable String deviceId) {
        List<String> args = new ArrayList<>();
        args.add("adb");
        if (ZaStrUtil.isNotBlank(deviceId)) {
            args.add("-s");
            args.add(deviceId);
        }
        return args;
    }

    private void runAsync(@NotNull GeneralCommandLine cmd,
                          @NotNull Consumer<AdbResult> onDone,
                          @NotNull Consumer<Throwable> onError) {
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                CapturingProcessHandler handler = new CapturingProcessHandler(cmd);
                ProcessOutput out = handler.runProcess(DEFAULT_TIMEOUT_MS);
                AdbResult result = new AdbResult(out);
                ApplicationManager.getApplication().invokeLater(() -> onDone.accept(result));
            } catch (Throwable t) {
                ApplicationManager.getApplication().invokeLater(() -> onError.accept(t));
            }
        });
    }

    private static final class AdbResult {
        private final int exitCode;
        private final String stdout;
        private final String stderr;

        private AdbResult(@NotNull ProcessOutput out) {
            this.exitCode = out.getExitCode();
            this.stdout = trim(out.getStdout());
            this.stderr = trim(out.getStderr());
        }
    }

    private static @NotNull String trim(@Nullable String value) {
        if (value == null) {
            return "";
        }
        return value.trim();
    }
}
