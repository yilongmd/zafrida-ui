package com.zafrida.ui.frida;

import com.intellij.execution.ExecutionException;
import com.intellij.execution.configurations.CommandLineTokenizer;
import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.execution.process.CapturingProcessHandler;
import com.intellij.execution.process.OSProcessHandler;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.zafrida.ui.python.ProjectPythonEnvResolver;
import com.zafrida.ui.python.PythonEnvInfo;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.settings.ZaFridaSettingsState;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * [核心服务] Frida 命令行工具执行网关。
 * <p>
 * <strong>核心职责：</strong>
 * 1. 封装 `frida`, `frida-ps`, `frida-ls-devices` 的调用逻辑。
 * 2. 负责将 {@link com.zafrida.ui.frida.FridaRunConfig} 转换为实际的 {@link GeneralCommandLine}。
 * 3. <strong>关键逻辑：</strong> 必须调用 {@link ProjectPythonEnvResolver} 注入 Python 环境，否则会报 "command not found"。
 * <p>
 * 注意：所有命令输出强制使用 UTF-8 编码以支持中文应用名。
 */
public final class FridaCliService {

    private static final Logger LOG = Logger.getInstance(FridaCliService.class);

    private final ZaFridaSettingsService settings;

    public FridaCliService() {
        this.settings = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
    }

    public @NotNull List<FridaDevice> listDevices(@NotNull Project project) {
        GeneralCommandLine cmd = buildLsDevicesCommandLine(project);
        CapturedOut out = runCapturing(cmd, 15_000);
        return FridaOutputParsers.parseDevices(out.stdout);
    }

    public @NotNull List<FridaProcess> listProcesses(@NotNull Project project,
                                                     @NotNull FridaDevice device,
                                                     @NotNull FridaProcessScope scope) {
        GeneralCommandLine cmd = buildPsCommandLine(project, device, scope);
        CapturedOut out = runCapturing(cmd, 20_000);
        return FridaOutputParsers.parseProcesses(out.stdout);
    }

    public @NotNull GeneralCommandLine buildRunCommandLine(@NotNull Project project, @NotNull FridaRunConfig config) {
        ZaFridaSettingsState s = settings.getState();
        GeneralCommandLine cmd = new GeneralCommandLine(s.fridaExecutable)
                .withCharset(StandardCharsets.UTF_8);

        applyProjectPythonEnv(project, cmd);

        addDeviceArgs(cmd, config.getDevice());

        FridaRunMode mode = config.getMode();
        if (mode instanceof FrontmostRunMode) {
            cmd.addParameter("-F");
        } else if (mode instanceof SpawnRunMode) {
            cmd.addParameters("-f", ((SpawnRunMode) mode).getIdentifier());
        } else if (mode instanceof AttachPidRunMode) {
            cmd.addParameters("-p", String.valueOf(((AttachPidRunMode) mode).getPid()));
        } else if (mode instanceof AttachNameRunMode) {
            cmd.addParameters("-n", ((AttachNameRunMode) mode).getName());
        } else {
            throw new IllegalArgumentException("Unknown run mode: " + mode);
        }

        cmd.addParameters("-l", config.getScriptPath());

        String extra = config.getExtraArgs();
        if (extra != null && !extra.trim().isEmpty()) {
            CommandLineTokenizer tok = new CommandLineTokenizer(extra);
            while (tok.hasMoreTokens()) {
                cmd.addParameter(tok.nextToken());
            }
        }

        return cmd;
    }

    public @NotNull OSProcessHandler createRunProcessHandler(@NotNull Project project, @NotNull FridaRunConfig config) {
        try {
            return new OSProcessHandler(buildRunCommandLine(project, config));
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    private @NotNull GeneralCommandLine buildLsDevicesCommandLine(@NotNull Project project) {
        ZaFridaSettingsState s = settings.getState();
        GeneralCommandLine cmd = new GeneralCommandLine(s.fridaLsDevicesExecutable)
                .withCharset(StandardCharsets.UTF_8);
        applyProjectPythonEnv(project, cmd);
        return cmd;
    }

    private @NotNull GeneralCommandLine buildPsCommandLine(@NotNull Project project,
                                                           @NotNull FridaDevice device,
                                                           @NotNull FridaProcessScope scope) {
        ZaFridaSettingsState s = settings.getState();
        GeneralCommandLine cmd = new GeneralCommandLine(s.fridaPsExecutable)
                .withCharset(StandardCharsets.UTF_8);

        applyProjectPythonEnv(project, cmd);

        addDeviceArgs(cmd, device);

        switch (scope) {
            case RUNNING_PROCESSES -> {
                // default
            }
            case RUNNING_APPS -> cmd.addParameter("-a");
            case INSTALLED_APPS -> cmd.addParameters("-a", "-i");
        }

        return cmd;
    }

    private void applyProjectPythonEnv(@NotNull Project project, @NotNull GeneralCommandLine cmd) {
        // Make sure we inherit the parent environment, then prepend the project interpreter's PATH.
        cmd.withParentEnvironmentType(GeneralCommandLine.ParentEnvironmentType.CONSOLE);
        PythonEnvInfo env = ProjectPythonEnvResolver.resolve(project);
        if (env != null) {
            ProjectPythonEnvResolver.applyToCommandLine(cmd, env);
        }
    }

    private void addDeviceArgs(@NotNull GeneralCommandLine cmd, @NotNull FridaDevice device) {
        if (device.getMode() == FridaDeviceMode.HOST) {
            String host = device.getHost();
            if (host == null || host.isBlank()) {
                throw new IllegalArgumentException("Device host is null/blank");
            }
            cmd.addParameters("-H", host);
            return;
        }
        String id = device.getId();
        if ("usb".equalsIgnoreCase(id)) {
            cmd.addParameter("-U");
        } else {
            cmd.addParameters("-D", id);
        }
    }

    private CapturedOut runCapturing(@NotNull GeneralCommandLine cmd, int timeoutMs) {
        CapturingProcessHandler handler = null;
        try {
            handler = new CapturingProcessHandler(cmd);
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
        var out = handler.runProcess(timeoutMs);

        String stdout = out.getStdout() != null ? out.getStdout() : "";
        String stderr = out.getStderr() != null ? out.getStderr() : "";
        int exitCode = out.getExitCode();

        if (exitCode != 0) {
            String cmdLine = cmd.getCommandLineString();
            LOG.warn("Frida tool failed: exit=" + exitCode + " cmd=" + cmdLine + " stderr=" + stderr + " stdout=" + stdout);
            throw new FridaCliException(
                    "Command failed (exit=" + exitCode + "): " + cmdLine + "\n" + stderr,
                    cmdLine,
                    exitCode,
                    stdout,
                    stderr
            );
        }

        return new CapturedOut(stdout, stderr, exitCode);
    }
}
