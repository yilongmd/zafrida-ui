package com.zafrida.ui.diagnostics;

import com.intellij.execution.ExecutionException;
import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.execution.process.CapturingProcessHandler;
import com.intellij.execution.process.ProcessOutput;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.application.ModalityState;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.SystemInfoRt;
import com.zafrida.ui.adb.AdbService;
import com.zafrida.ui.frida.FridaCliService;
import com.zafrida.ui.frida.FridaDevice;
import com.zafrida.ui.frida.FridaOutputParsers;
import com.zafrida.ui.frida.FridaProcessScope;
import com.zafrida.ui.python.ProjectPythonEnvResolver;
import com.zafrida.ui.python.PythonEnvInfo;
import com.zafrida.ui.python.PythonEnvResolutionException;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.settings.ZaFridaSettingsState;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public final class ZaFridaDiagnosticsService {

    private static final Logger LOG = Logger.getInstance(ZaFridaDiagnosticsService.class);
    private static final int POLL_INTERVAL_MS = 200;

    private static final String TIP_PYTHON_SDK =
            "Tip: Configure the active ZAFrida project's Python environment, or configure the PyCharm project interpreter. "
                    + "(提示: 请配置当前 ZAFrida 项目的 Python 环境，或配置 PyCharm 项目解释器。)";
    private static final String TIP_TOOL_PATH =
            "Tip: Set correct frida/frida-ps/frida-ls-devices path in ZAFrida Settings. (提示: 请在 ZAFrida Settings 中设置正确的 frida/frida-ps/frida-ls-devices 路径。)";
    private static final String TIP_FRIDA_VERSION =
            "Tip: Ensure frida-tools is installed in current Python env. (提示: 请确认 frida-tools 已安装并在当前 Python 环境可用。)";
    private static final String TIP_LS_DEVICES =
            "Tip: Ensure frida-server is running and connection works. (提示: 请确认 frida-server 已启动，且 USB/远程连接正常。)";
    private static final String TIP_DEVICE_PS =
            "Tip: Ensure device is connected and frida-server version matches. (提示: 请确认设备已连接且 frida-server 版本匹配。)";
    private static final String TIP_ADB =
            "Tip: Ensure adb is installed and in PATH (Android SDK). (提示: 请确认 adb 已安装并加入 PATH（Android SDK）。)";

    private final FridaCliService fridaCli;
    private final AdbService adbService;
    private final ZaFridaSettingsService settingsService;

    public ZaFridaDiagnosticsService() {
        this.fridaCli = ApplicationManager.getApplication().getService(FridaCliService.class);
        this.adbService = ApplicationManager.getApplication().getService(AdbService.class);
        this.settingsService = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
    }

    public @NotNull List<ZaFridaDiagnosticItem> createDefaultItems() {
        List<ZaFridaDiagnosticItem> items = new ArrayList<>();

        items.add(buildPythonSdkItem());
        items.add(buildFridaToolPathsItem());
        items.add(buildFridaVersionItem());
        items.add(buildLsDevicesItem());
        items.add(buildDevicePsItem());
        items.add(buildAdbItem());

        return items;
    }

    private @NotNull ZaFridaDiagnosticItem buildPythonSdkItem() {
        return new ZaFridaDiagnosticItem(
                "python-sdk",
                "Python Environment",
                "Resolve the active ZAFrida project's effective Python interpreter (解析当前 ZAFrida 项目的实际 Python 解释器)",
                3_000,
                new ZaFridaDiagnosticTask() {
                    @Override
                    public @NotNull ZaFridaDiagnosticResult run(@NotNull ZaFridaDiagnosticsContext context) {
                        return checkPythonSdk(context);
                    }
                }
        );
    }

    private @NotNull ZaFridaDiagnosticItem buildFridaToolPathsItem() {
        return new ZaFridaDiagnosticItem(
                "frida-tool-paths",
                "Frida Tools Path",
                "Check frida / frida-ps / frida-ls-devices paths (检查 frida / frida-ps / frida-ls-devices 路径)",
                3_000,
                new ZaFridaDiagnosticTask() {
                    @Override
                    public @NotNull ZaFridaDiagnosticResult run(@NotNull ZaFridaDiagnosticsContext context) {
                        return checkFridaToolPaths(context);
                    }
                }
        );
    }

    private @NotNull ZaFridaDiagnosticItem buildFridaVersionItem() {
        return new ZaFridaDiagnosticItem(
                "frida-version",
                "frida --version",
                "Verify frida executable and version output (验证 frida 可执行与版本输出)",
                8_000,
                new ZaFridaDiagnosticTask() {
                    @Override
                    public @NotNull ZaFridaDiagnosticResult run(@NotNull ZaFridaDiagnosticsContext context) throws Exception {
                        return checkFridaVersion(context);
                    }
                }
        );
    }

    private @NotNull ZaFridaDiagnosticItem buildLsDevicesItem() {
        return new ZaFridaDiagnosticItem(
                "frida-ls-devices",
                "frida-ls-devices",
                "Check whether device listing works (检查设备枚举是否可用)",
                10_000,
                new ZaFridaDiagnosticTask() {
                    @Override
                    public @NotNull ZaFridaDiagnosticResult run(@NotNull ZaFridaDiagnosticsContext context) throws Exception {
                        return checkLsDevices(context);
                    }
                }
        );
    }

    private @NotNull ZaFridaDiagnosticItem buildDevicePsItem() {
        return new ZaFridaDiagnosticItem(
                "device-ps",
                "Selected Device Connectivity",
                "Validate selected device via frida-ps (使用 frida-ps 验证当前选中设备)",
                12_000,
                new ZaFridaDiagnosticTask() {
                    @Override
                    public @NotNull ZaFridaDiagnosticResult run(@NotNull ZaFridaDiagnosticsContext context) throws Exception {
                        return checkDevicePs(context);
                    }
                }
        );
    }

    private @NotNull ZaFridaDiagnosticItem buildAdbItem() {
        return new ZaFridaDiagnosticItem(
                "adb-version",
                "adb availability",
                "Check adb availability (检查 adb 是否可用)",
                8_000,
                new ZaFridaDiagnosticTask() {
                    @Override
                    public @NotNull ZaFridaDiagnosticResult run(@NotNull ZaFridaDiagnosticsContext context) throws Exception {
                        return checkAdb(context);
                    }
                }
        );
    }

    public void runDiagnostics(@NotNull Project project,
                               @Nullable FridaDevice device,
                               @NotNull List<ZaFridaDiagnosticItem> items,
                               @NotNull ZaFridaDiagnosticsListener listener) {
        if (project.isDisposed()) {
            return;
        }
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            ZaFridaSettingsState settings = settingsService.getState();
            PythonEnvInfo env = null;
            String pythonEnvError = null;
            try {
                env = ProjectPythonEnvResolver.resolve(project);
            } catch (PythonEnvResolutionException e) {
                pythonEnvError = e.getMessage();
                LOG.warn("Resolve configured ZAFrida Python environment failed", e);
            }
            ZaFridaDiagnosticsContext context = new ZaFridaDiagnosticsContext(
                    project,
                    device,
                    settings,
                    env,
                    pythonEnvError
            );

            for (ZaFridaDiagnosticItem item : items) {
                if (item.isSkipRequested()) {
                    updateItem(item, ZaFridaDiagnosticStatus.SKIPPED, null, null, listener);
                    continue;
                }

                updateItem(item, ZaFridaDiagnosticStatus.RUNNING, null, null, listener);

                ZaFridaDiagnosticResult result = runWithTimeout(item, context);

                if (item.isSkipRequested()) {
                    updateItem(item, ZaFridaDiagnosticStatus.SKIPPED, null, null, listener);
                    continue;
                }

                applyResult(item, result, listener);
            }

            notifyAllCompleted(listener, items);
        });
    }

    private @NotNull ZaFridaDiagnosticResult checkPythonSdk(@NotNull ZaFridaDiagnosticsContext context) {
        if (ZaStrUtil.isNotBlank(context.getPythonEnvError())) {
            return ZaFridaDiagnosticResult.failed(context.getPythonEnvError(), TIP_PYTHON_SDK);
        }
        PythonEnvInfo env = context.getPythonEnv();
        if (env == null) {
            return ZaFridaDiagnosticResult.failed("Project Python SDK not resolved (未解析到 Project Python SDK)", TIP_PYTHON_SDK);
        }
        String home = env.getPythonHome();
        if (ZaStrUtil.isBlank(home)) {
            return ZaFridaDiagnosticResult.failed("Python interpreter path is empty (Python 解释器路径为空)", TIP_PYTHON_SDK);
        }
        String source = "PyCharm project";
        if (env.getSource() == PythonEnvInfo.Source.ZAFRIDA_PROJECT) {
            source = "ZAFrida project override";
        }
        return ZaFridaDiagnosticResult.success(String.format("Python (%s): %s", source, home));
    }

    private @NotNull ZaFridaDiagnosticResult checkFridaToolPaths(@NotNull ZaFridaDiagnosticsContext context) {
        if (ZaStrUtil.isNotBlank(context.getPythonEnvError())) {
            return ZaFridaDiagnosticResult.failed(context.getPythonEnvError(), TIP_TOOL_PATH);
        }
        ZaFridaSettingsState settings = context.getSettings();
        PythonEnvInfo env = context.getPythonEnv();

        String frida = settings.fridaExecutable;
        String fridaPs = settings.fridaPsExecutable;
        String fridaLs = settings.fridaLsDevicesExecutable;

        String fridaPath = resolveToolPath(frida, env);
        String fridaPsPath = resolveToolPath(fridaPs, env);
        String fridaLsPath = resolveToolPath(fridaLs, env);

        StringBuilder message = new StringBuilder("<html>");
        appendToolLine(message, "frida", fridaPath);
        appendToolLine(message, "frida-ps", fridaPsPath);
        appendToolLine(message, "frida-ls-devices", fridaLsPath);
        message.append("</html>");

        boolean missing = false;
        if (fridaPath == null) {
            missing = true;
        }
        if (fridaPsPath == null) {
            missing = true;
        }
        if (fridaLsPath == null) {
            missing = true;
        }

        if (missing) {
            return ZaFridaDiagnosticResult.failed(message.toString(), TIP_TOOL_PATH);
        }
        return ZaFridaDiagnosticResult.success(message.toString());
    }

    private void appendToolLine(@NotNull StringBuilder message,
                                @NotNull String name,
                                @Nullable String path) {
        message.append(name).append(": ");
        if (ZaStrUtil.isBlank(path)) {
            message.append("Not found (未找到)");
        } else {
            message.append(path);
        }
        message.append("<br/>");
    }

    private @NotNull ZaFridaDiagnosticResult checkFridaVersion(@NotNull ZaFridaDiagnosticsContext context) throws Exception {
        GeneralCommandLine cmd = fridaCli.buildFridaVersionCommandLine(context.getProject());
        CommandResult result = runCommand(cmd, 8_000);
        if (result.exitCode != 0) {
            String detail = preferStdErr(result);
            return ZaFridaDiagnosticResult.failed(
                    String.format("frida --version failed: %s (frida --version 失败: %s)", detail, detail),
                    TIP_FRIDA_VERSION
            );
        }
        String text = ZaStrUtil.trim(result.stdout);
        if (ZaStrUtil.isBlank(text)) {
            text = "frida --version ok";
        }
        return ZaFridaDiagnosticResult.success(text);
    }

    private @NotNull ZaFridaDiagnosticResult checkLsDevices(@NotNull ZaFridaDiagnosticsContext context) throws Exception {
        GeneralCommandLine cmd = fridaCli.buildLsDevicesCommandLineForDiagnostics(context.getProject());
        CommandResult result = runCommand(cmd, 10_000);
        if (result.exitCode != 0) {
            String detail = preferStdErr(result);
            return ZaFridaDiagnosticResult.failed(
                    String.format("frida-ls-devices failed: %s (frida-ls-devices 失败: %s)", detail, detail),
                    TIP_LS_DEVICES
            );
        }

        int count = FridaOutputParsers.parseDevices(result.stdout).size();
        return ZaFridaDiagnosticResult.success(String.format("Devices: %s (设备数量: %s)", count, count));
    }

    private @NotNull ZaFridaDiagnosticResult checkDevicePs(@NotNull ZaFridaDiagnosticsContext context) throws Exception {
        FridaDevice device = context.getDevice();
        if (device == null) {
            return ZaFridaDiagnosticResult.skipped("No device selected (未选择设备)", TIP_DEVICE_PS);
        }

        GeneralCommandLine cmd = fridaCli.buildPsCommandLineForDiagnostics(
                context.getProject(),
                device,
                FridaProcessScope.RUNNING_PROCESSES
        );
        CommandResult result = runCommand(cmd, 12_000);
        if (result.exitCode != 0) {
            String detail = preferStdErr(result);
            return ZaFridaDiagnosticResult.failed(
                    String.format("frida-ps failed: %s (frida-ps 失败: %s)", detail, detail),
                    TIP_DEVICE_PS
            );
        }

        int count = FridaOutputParsers.parseProcesses(result.stdout).size();
        return ZaFridaDiagnosticResult.success(
                String.format("frida-ps ok, processes: %s (frida-ps ok, 进程数: %s)", count, count)
        );
    }

    private @NotNull ZaFridaDiagnosticResult checkAdb(@NotNull ZaFridaDiagnosticsContext context) throws Exception {
        GeneralCommandLine cmd = adbService.buildVersionCommandLine();
        CommandResult result = runCommand(cmd, 8_000);
        if (result.exitCode != 0) {
            String detail = preferStdErr(result);
            return ZaFridaDiagnosticResult.failed(
                    String.format("adb not available: %s (adb 不可用: %s)", detail, detail),
                    TIP_ADB
            );
        }

        String stdout = ZaStrUtil.trim(result.stdout);
        String firstLine = firstLine(stdout);
        if (ZaStrUtil.isBlank(firstLine)) {
            firstLine = "adb ok";
        }
        return ZaFridaDiagnosticResult.success(firstLine);
    }

    private @NotNull ZaFridaDiagnosticResult runWithTimeout(@NotNull ZaFridaDiagnosticItem item,
                                                            @NotNull ZaFridaDiagnosticsContext context) {
        Future<ZaFridaDiagnosticResult> future = ApplicationManager.getApplication()
                .executeOnPooledThread(() -> item.getTask().run(context));
        long start = System.currentTimeMillis();
        while (true) {
            if (item.isSkipRequested()) {
                future.cancel(true);
                return ZaFridaDiagnosticResult.skipped(null, null);
            }

            long elapsed = System.currentTimeMillis() - start;
            long remaining = item.getTimeoutMs() - elapsed;
            if (remaining <= 0) {
                future.cancel(true);
                return ZaFridaDiagnosticResult.timeout(
                        String.format("Timeout (%sms) (超时（%sms）)", item.getTimeoutMs(), item.getTimeoutMs()),
                        "Tip: This check timed out, retry or skip. (提示: 该检查超时，可稍后重试或选择跳过。)"
                );
            }

            long waitMs = remaining;
            if (waitMs > POLL_INTERVAL_MS) {
                waitMs = POLL_INTERVAL_MS;
            }

            try {
                return future.get(waitMs, TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
                continue;
            } catch (java.util.concurrent.ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause != null) {
                    LOG.warn("Diagnostics task failed", cause);
                    return ZaFridaDiagnosticResult.failed(
                            cause.getMessage(),
                            "Tip: Check failed, see logs or retry. (提示: 该检查执行失败，请查看日志或重试。)"
                    );
                }
                return ZaFridaDiagnosticResult.failed(
                        "Diagnostics failed (诊断执行失败)",
                        "Tip: Check failed, see logs or retry. (提示: 该检查执行失败，请查看日志或重试。)"
                );
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return ZaFridaDiagnosticResult.failed(
                        "Diagnostics interrupted (诊断被中断)",
                        "Tip: Diagnostics interrupted, please retry. (提示: 诊断被中断，请重试。)"
                );
            }
        }
    }

    private void applyResult(@NotNull ZaFridaDiagnosticItem item,
                             @NotNull ZaFridaDiagnosticResult result,
                             @NotNull ZaFridaDiagnosticsListener listener) {
        item.updateStatus(result.getStatus(), result.getMessage(), result.getTip());
        notifyItemUpdated(listener, item);
    }

    private void updateItem(@NotNull ZaFridaDiagnosticItem item,
                            @NotNull ZaFridaDiagnosticStatus status,
                            @Nullable String message,
                            @Nullable String tip,
                            @NotNull ZaFridaDiagnosticsListener listener) {
        item.updateStatus(status, message, tip);
        notifyItemUpdated(listener, item);
    }

    private void notifyItemUpdated(@NotNull ZaFridaDiagnosticsListener listener,
                                   @NotNull ZaFridaDiagnosticItem item) {
        ApplicationManager.getApplication().invokeLater(
                () -> listener.onItemUpdated(item),
                ModalityState.any()
        );
    }

    private void notifyAllCompleted(@NotNull ZaFridaDiagnosticsListener listener,
                                    @NotNull List<ZaFridaDiagnosticItem> items) {
        ApplicationManager.getApplication().invokeLater(
                () -> listener.onAllCompleted(items),
                ModalityState.any()
        );
    }

    private @NotNull CommandResult runCommand(@NotNull GeneralCommandLine cmd, int timeoutMs) throws ExecutionException {
        CapturingProcessHandler handler = new CapturingProcessHandler(cmd);
        ProcessOutput output = handler.runProcess(timeoutMs);
        return new CommandResult(output);
    }

    private @Nullable String resolveToolPath(@Nullable String tool,
                                             @Nullable PythonEnvInfo env) {
        if (ZaStrUtil.isBlank(tool)) {
            return null;
        }

        String name = ZaStrUtil.trim(tool);
        if (ZaStrUtil.isBlank(name)) {
            return null;
        }

        if (env != null && env.getSource() == PythonEnvInfo.Source.ZAFRIDA_PROJECT) {
            return ProjectPythonEnvResolver.findTool(env, executableFileName(name));
        }

        Path path;
        try {
            path = Paths.get(name);
        } catch (InvalidPathException e) {
            return null;
        }

        if (path.isAbsolute()) {
            if (Files.isRegularFile(path)) {
                return path.toAbsolutePath().toString();
            }
            return null;
        }

        if (env != null) {
            String found = ProjectPythonEnvResolver.findTool(env, name);
            return found;
        }

        return findOnPath(name);
    }

    private @NotNull String executableFileName(@NotNull String executable) {
        try {
            Path fileName = Paths.get(executable).getFileName();
            if (fileName != null) {
                return fileName.toString();
            }
        } catch (InvalidPathException e) {
            LOG.debug(String.format("Cannot parse executable path, use original value: %s", executable), e);
        }
        return executable;
    }

    private @Nullable String findOnPath(@NotNull String tool) {
        String pathValue = System.getenv("PATH");
        if (ZaStrUtil.isBlank(pathValue)) {
            pathValue = System.getenv("Path");
        }
        if (ZaStrUtil.isBlank(pathValue)) {
            return null;
        }

        String[] parts = pathValue.split(java.util.regex.Pattern.quote(File.pathSeparator));
        List<String> names = buildCandidateNames(tool);
        for (String dir : parts) {
            if (ZaStrUtil.isBlank(dir)) {
                continue;
            }
            Path base;
            try {
                base = Paths.get(dir);
            } catch (InvalidPathException e) {
                continue;
            }

            for (String name : names) {
                Path file = base.resolve(name);
                if (Files.isRegularFile(file)) {
                    return file.toAbsolutePath().toString();
                }
            }
        }
        return null;
    }

    private @NotNull List<String> buildCandidateNames(@NotNull String baseName) {
        List<String> out = new ArrayList<>();
        out.add(baseName);

        if (SystemInfoRt.isWindows) {
            String lower = baseName.toLowerCase(Locale.ROOT);
            if (!lower.endsWith(".exe")) {
                out.add(String.format("%s.exe", baseName));
            }
            if (!lower.endsWith(".cmd")) {
                out.add(String.format("%s.cmd", baseName));
            }
            if (!lower.endsWith(".bat")) {
                out.add(String.format("%s.bat", baseName));
            }
        }

        return out;
    }

    private @NotNull String preferStdErr(@NotNull CommandResult result) {
        if (ZaStrUtil.isNotBlank(result.stderr)) {
            return result.stderr;
        }
        if (ZaStrUtil.isNotBlank(result.stdout)) {
            return result.stdout;
        }
        return "unknown error";
    }

    private @Nullable String firstLine(@Nullable String text) {
        if (ZaStrUtil.isBlank(text)) {
            return null;
        }
        String[] lines = text.split("\\R");
        if (lines.length == 0) {
            return null;
        }
        String line = ZaStrUtil.trim(lines[0]);
        if (ZaStrUtil.isBlank(line)) {
            return null;
        }
        return line;
    }

    private static final class CommandResult {
        private final int exitCode;
        private final String stdout;
        private final String stderr;

        private CommandResult(@NotNull ProcessOutput output) {
            this.exitCode = output.getExitCode();
            String stdoutValue = ZaStrUtil.trim(output.getStdout());
            String stderrValue = ZaStrUtil.trim(output.getStderr());
            this.stdout = ZaStrUtil.nullToEmpty(stdoutValue);
            this.stderr = ZaStrUtil.nullToEmpty(stderrValue);
        }
    }
}
