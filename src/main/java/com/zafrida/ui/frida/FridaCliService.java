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

    /** 日志记录器 */
    private static final Logger LOG = Logger.getInstance(FridaCliService.class);

    /** 设置服务 */
    private final ZaFridaSettingsService settings;

    /**
     * 构造函数。
     */
    public FridaCliService() {
        this.settings = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
    }

    /**
     * 列出当前可用设备。
     * @param project 当前 IDE 项目
     * @return 设备列表
     */
    public @NotNull List<FridaDevice> listDevices(@NotNull Project project) {
        GeneralCommandLine cmd = buildLsDevicesCommandLine(project);
        CapturedOut out = runCapturing(cmd, 15_000);
        return FridaOutputParsers.parseDevices(out.stdout);
    }

    /**
     * 列出设备上的进程或应用。
     * @param project 当前 IDE 项目
     * @param device 目标设备
     * @param scope 列表作用域
     * @return 进程/应用列表
     */
    public @NotNull List<FridaProcess> listProcesses(@NotNull Project project,
                                                     @NotNull FridaDevice device,
                                                     @NotNull FridaProcessScope scope) {
        GeneralCommandLine cmd = buildPsCommandLine(project, device, scope);
        CapturedOut out = runCapturing(cmd, 20_000);
        return FridaOutputParsers.parseProcesses(out.stdout);
    }

    /**
     * 构建执行 Frida 的命令行对象。
     * @param project 当前 IDE 项目
     * @param config 运行配置
     * @return GeneralCommandLine
     */
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
            cmd.addParameters("-N", ((AttachNameRunMode) mode).getName());
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

    /**
     * 创建并返回运行进程处理器。
     * @param project 当前 IDE 项目
     * @param config 运行配置
     * @return OSProcessHandler
     */
    public @NotNull OSProcessHandler createRunProcessHandler(@NotNull Project project, @NotNull FridaRunConfig config) {
        try {
            return new OSProcessHandler(buildRunCommandLine(project, config));
        } catch (ExecutionException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 构建 frida-ls-devices 命令行。
     * @param project 当前 IDE 项目
     * @return GeneralCommandLine
     */
    private @NotNull GeneralCommandLine buildLsDevicesCommandLine(@NotNull Project project) {
        ZaFridaSettingsState s = settings.getState();
        GeneralCommandLine cmd = new GeneralCommandLine(s.fridaLsDevicesExecutable)
                .withCharset(StandardCharsets.UTF_8);
        applyProjectPythonEnv(project, cmd);
        return cmd;
    }

    /**
     * 构建 frida-ps 命令行。
     * @param project 当前 IDE 项目
     * @param device 目标设备
     * @param scope 查询范围
     * @return GeneralCommandLine
     */
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
                // 默认行为
            }
            case RUNNING_APPS -> cmd.addParameter("-a");
            case INSTALLED_APPS -> cmd.addParameters("-a", "-i");
        }

        return cmd;
    }

    /**
     * 注入项目 Python 环境到命令行。
     * @param project 当前 IDE 项目
     * @param cmd 命令行对象
     */
    private void applyProjectPythonEnv(@NotNull Project project, @NotNull GeneralCommandLine cmd) {
        // Make sure we inherit the parent environment, then prepend the project interpreter's PATH.
        // 确保继承父环境变量，并将项目解释器路径追加到 PATH 前面。
        cmd.withParentEnvironmentType(GeneralCommandLine.ParentEnvironmentType.CONSOLE);
        PythonEnvInfo env = ProjectPythonEnvResolver.resolve(project);
        if (env != null) {
            ProjectPythonEnvResolver.applyToCommandLine(cmd, env);
        }
    }

    /**
     * 根据设备信息添加连接参数。
     * @param cmd 命令行对象
     * @param device 目标设备
     */
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

    /**
     * 执行命令并捕获输出。
     * @param cmd 命令行对象
     * @param timeoutMs 超时时间（毫秒）
     * @return 捕获结果
     */
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
