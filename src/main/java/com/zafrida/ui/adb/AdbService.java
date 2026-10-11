package com.zafrida.ui.adb;

import com.intellij.execution.ExecutionException;
import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.execution.process.CapturingProcessHandler;
import com.intellij.execution.process.ProcessOutput;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.util.EnvironmentUtil;
import com.zafrida.ui.util.ZaFridaNetUtil;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public final class AdbService {

    private static final Logger LOG = Logger.getInstance(AdbService.class);
    private static final String ADB_EXECUTABLE = "adb";
    private static final int DEFAULT_TIMEOUT_MS = 10_000;
    /** 冷启动 daemon 加上 adb 自带的最长 3 秒初始 USB 扫描等待。 */
    private static final int START_SERVER_TIMEOUT_MS = 15_000;
    private static final String DAEMON_NOT_RUNNING_MARKER = "daemon not running";
    private static final String DAEMON_STARTED_MARKER = "daemon started";
    private static final String ADB_SERVER_PORT_ENV = "ANDROID_ADB_SERVER_PORT";
    private static final int DEFAULT_ADB_SERVER_PORT = 5037;
    private static final int SERVER_PROBE_TIMEOUT_MS = 300;

    /**
     * 确保 adb server 在运行，只允许在后台线程调用（同步）。
     * Frida 通过本机 adb server 枚举 Android 设备，但不会自己拉起它；server 未运行时设备列表为空。
     * 已在监听时不启动任何进程；否则执行 {@code adb start-server}，adb 自身会等待初始 USB 扫描完成。
     */
    public @NotNull ServerStartResult ensureServerStarted() {
        if (isServerListening()) {
            return new ServerStartResult(ServerStartStatus.ALREADY_RUNNING, "");
        }
        GeneralCommandLine cmd = new GeneralCommandLine(ADB_EXECUTABLE, "start-server")
                .withCharset(StandardCharsets.UTF_8);
        ProcessOutput out;
        try {
            CapturingProcessHandler handler = new CapturingProcessHandler(cmd);
            out = handler.runProcess(START_SERVER_TIMEOUT_MS);
        } catch (ExecutionException e) {
            // 没装 adb 是 iOS/纯 Remote 用户的正常状态，只记日志不打扰界面。
            LOG.info(String.format("adb is not available, skip starting ADB server: %s", e.getMessage()));
            return new ServerStartResult(ServerStartStatus.UNAVAILABLE, trim(e.getMessage()));
        }
        String output = String.format("%s\n%s", trim(out.getStdout()), trim(out.getStderr())).trim();
        if (out.isTimeout()) {
            LOG.warn(String.format("adb start-server timed out after %s ms", START_SERVER_TIMEOUT_MS));
            return new ServerStartResult(ServerStartStatus.FAILED, "adb start-server timed out");
        }
        if (out.getExitCode() != 0) {
            LOG.warn(String.format("adb start-server failed (exitCode=%s): %s", out.getExitCode(), output));
            return new ServerStartResult(ServerStartStatus.FAILED, output);
        }
        if (output.contains(DAEMON_NOT_RUNNING_MARKER) || output.contains(DAEMON_STARTED_MARKER)) {
            return new ServerStartResult(ServerStartStatus.STARTED, output);
        }
        return new ServerStartResult(ServerStartStatus.ALREADY_RUNNING, output);
    }

    /**
     * 端口探测只是为了省掉每次枚举都起一个 adb 进程；探测不到（含自定义 socket）一律交给
     * {@code adb start-server} 判断，所以这里误判为未监听是安全的。
     */
    private static boolean isServerListening() {
        int port = resolveServerPort();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ZaFridaNetUtil.LOOPBACK_HOST, port), SERVER_PROBE_TIMEOUT_MS);
            return true;
        } catch (IOException e) {
            LOG.debug(String.format("ADB server is not listening on port %s: %s", port, e.getMessage()));
            return false;
        }
    }

    private static int resolveServerPort() {
        int configured = ZaFridaNetUtil.parsePort(EnvironmentUtil.getValue(ADB_SERVER_PORT_ENV));
        if (configured > 0) {
            return configured;
        }
        return DEFAULT_ADB_SERVER_PORT;
    }

    /** onDone 总会被调用，参数表示转发是否成功；是否继续启动会话由调用方决定。 */
    public void forwardTcp(int port,
                           @Nullable String deviceId,
                           @NotNull Consumer<String> info,
                           @NotNull Consumer<String> warn,
                           @NotNull Consumer<Boolean> onDone) {
        GeneralCommandLine cmd = buildForwardCommand(port, deviceId);
        info.accept(String.format("[ZAFrida] ADB forward: %s", cmd.getCommandLineString()));

        runAsync(cmd, result -> {
            boolean success = result.exitCode == 0;
            if (success) {
                info.accept(String.format("[ZAFrida] ADB forward ready on port %s", port));
            } else {
                warn.accept(String.format("[ZAFrida] ADB forward failed (exitCode=%s)", result.exitCode));
            }
            if (ZaStrUtil.isNotBlank(result.stdout)) {
                info.accept(String.format("[ZAFrida] %s", result.stdout));
            }
            if (ZaStrUtil.isNotBlank(result.stderr)) {
                warn.accept(String.format("[ZAFrida] %s", result.stderr));
            }
            onDone.accept(success);
        }, throwable -> {
            warn.accept(String.format("[ZAFrida] ADB forward failed: %s", throwable.getMessage()));
            onDone.accept(false);
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
        return new GeneralCommandLine(ADB_EXECUTABLE, "version")
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
        args.add(ADB_EXECUTABLE);
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

    public enum ServerStartStatus {
        /** 当前项目不使用 adb，未做任何检查。 */
        SKIPPED,
        ALREADY_RUNNING,
        STARTED,
        /** 找不到或无法执行 adb。 */
        UNAVAILABLE,
        FAILED
    }

    public static final class ServerStartResult {
        private final @NotNull ServerStartStatus status;
        private final @NotNull String detail;

        private ServerStartResult(@NotNull ServerStartStatus status, @NotNull String detail) {
            this.status = status;
            this.detail = detail;
        }

        public static @NotNull ServerStartResult skipped() {
            return new ServerStartResult(ServerStartStatus.SKIPPED, "");
        }

        public @NotNull ServerStartStatus getStatus() {
            return status;
        }

        public @NotNull String getDetail() {
            return detail;
        }
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
