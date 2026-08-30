package com.zafrida.ui.frida;

import com.intellij.execution.ExecutionException;
import com.intellij.execution.configurations.CommandLineTokenizer;
import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.execution.process.CapturingProcessHandler;
import com.intellij.execution.process.OSProcessHandler;
import com.intellij.execution.process.ProcessOutput;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.progress.ProcessCanceledException;
import com.intellij.openapi.util.SystemInfoRt;
import com.zafrida.ui.python.ProjectPythonEnvResolver;
import com.zafrida.ui.python.PythonEnvInfo;
import com.zafrida.ui.python.PythonEnvResolutionException;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.settings.ZaFridaSettingsState;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;

public final class FridaCliService {

    private static final Logger LOG = Logger.getInstance(FridaCliService.class);

    private static final int LIST_DEVICES_TIMEOUT_MS = 30_000;

    private static final String ENV_PYTHONIOENCODING = "PYTHONIOENCODING";
    private static final String ENV_PYTHONUTF8 = "PYTHONUTF8";
    private static final String ENV_PYTHONUNBUFFERED = "PYTHONUNBUFFERED";

    private static final String PY_ENUM_DEVICES_SCRIPT =
            "import frida\n"
                    + "def _type_str(v):\n"
                    + "    try:\n"
                    + "        if hasattr(v, 'value'):\n"
                    + "            return str(v.value)\n"
                    + "        if hasattr(v, 'name'):\n"
                    + "            return str(v.name)\n"
                    + "    except Exception:\n"
                    + "        pass\n"
                    + "    return str(v)\n"
                    + "print('Id  Type  Name')\n"
                    + "for d in frida.enumerate_devices():\n"
                    + "    t = _type_str(getattr(d, 'type', ''))\n"
                    + "    if t:\n"
                    + "        t = t.lower()\n"
                    + "    print(f\"{getattr(d, 'id', '')}  {t}  {getattr(d, 'name', '')}\")\n";
    private final ZaFridaSettingsService settings;
    private final Map<Project, String> detectedProjectVersions = Collections.synchronizedMap(new WeakHashMap<>());

    public FridaCliService() {
        this.settings = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
    }

    public @NotNull List<FridaDevice> listDevices(@NotNull Project project) {
        GeneralCommandLine cmd = buildLsDevicesCommandLine(project);
        try {
            CapturedOut out = runCapturing(cmd, LIST_DEVICES_TIMEOUT_MS);
            return FridaOutputParsers.parseDevices(out.stdout);
        } catch (FridaCliException e) {
            // 部分版本会在输出有效设备表后返回非零状态，优先保留可解析结果。
            List<FridaDevice> parsed = FridaOutputParsers.parseDevices(e.getStdout());
            if (!parsed.isEmpty()) {
                LOG.warn(String.format("frida-ls-devices returned non-zero but produced %s devices, use stdout anyway. exit=%s cmd=%s",
                        parsed.size(), e.getExitCode(), e.getCommandLine()));
                return parsed;
            }

            if (shouldFallbackToPythonForNoConsole(e)) {
                LOG.warn(String.format("frida-ls-devices failed due to missing Windows console, fallback to python frida enumeration. cmd=%s",
                        e.getCommandLine()));
                try {
                    return listDevicesViaPython(project);
                } catch (ProcessCanceledException canceled) {
                    throw canceled;
                } catch (Throwable t) {
                    // UI 保留原始错误，fallback 原因作为 suppressed exception 进入日志。
                    e.addSuppressed(t);
                    throw e;
                }
            }
            throw e;
        }
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
            cmd.addParameters("-N", ((AttachNameRunMode) mode).getName());
        } else {
            throw new IllegalArgumentException(String.format("Unknown run mode: %s", mode));
        }

        cmd.addParameters("-l", config.getScriptPath());

        String extra = config.getExtraArgs();
        if (ZaStrUtil.isNotBlank(extra)) {
            CommandLineTokenizer tok = new CommandLineTokenizer(extra);
            while (tok.hasMoreTokens()) {
                cmd.addParameter(tok.nextToken());
            }
        }

        return cmd;
    }

    public @NotNull OSProcessHandler createRunProcessHandler(@NotNull Project project, @NotNull FridaRunConfig config) {
        return createRunProcessHandler(buildRunCommandLine(project, config));
    }

    public @NotNull OSProcessHandler createRunProcessHandler(@NotNull GeneralCommandLine commandLine) {
        try {
            return new OSProcessHandler(commandLine);
        } catch (ExecutionException e) {
            throw processStartException(commandLine, e);
        }
    }

    public @NotNull GeneralCommandLine buildFridaVersionCommandLine(@NotNull Project project) {
        ZaFridaSettingsState s = settings.getState();
        GeneralCommandLine cmd = new GeneralCommandLine(s.fridaExecutable)
                .withCharset(StandardCharsets.UTF_8);
        applyProjectPythonEnv(project, cmd);
        cmd.addParameter("--version");
        return cmd;
    }

    public @NotNull String detectFridaPythonVersion(@NotNull PythonEnvInfo environment) {
        ZaFridaSettingsState state = settings.getState();
        String fridaExecutable = requireEnvironmentTool(environment, state.fridaExecutable);
        requireEnvironmentTool(environment, state.fridaPsExecutable);
        requireEnvironmentTool(environment, state.fridaLsDevicesExecutable);

        GeneralCommandLine commandLine = new GeneralCommandLine(fridaExecutable)
                .withCharset(StandardCharsets.UTF_8)
                .withParentEnvironmentType(GeneralCommandLine.ParentEnvironmentType.CONSOLE);
        applyPythonOutputEncodingEnv(commandLine);
        ProjectPythonEnvResolver.applyToCommandLine(commandLine, environment);
        commandLine.addParameter("--version");

        CapturedOut output = runCapturing(commandLine, 10_000);
        String version = output.stdout;
        if (version != null) {
            version = version.trim();
        }
        if (ZaStrUtil.isBlank(version)) {
            throw new PythonEnvResolutionException(String.format(
                    "The frida Python package returned no version: %s",
                    environment.getPythonHome()
            ));
        }
        return version;
    }

    public @NotNull String detectProjectFridaVersion(@NotNull Project project) {
        PythonEnvInfo environment = ProjectPythonEnvResolver.resolve(project);
        if (environment == null) {
            throw new PythonEnvResolutionException("The current project Python environment could not be resolved");
        }
        String version = detectFridaPythonVersion(environment);
        detectedProjectVersions.put(project, version);
        return version;
    }

    public boolean isFrida17OrLater(@NotNull Project project) {
        String detectedVersion = detectedProjectVersions.get(project);
        if (ZaStrUtil.isNotBlank(detectedVersion)) {
            return ZaStrUtil.compareVersion(detectedVersion, "17") >= 0;
        }
        return settings.isFrida17OrLater();
    }

    public void clearDetectedProjectVersion(@NotNull Project project) {
        detectedProjectVersions.remove(project);
    }

    public boolean hasDetectedProjectVersion(@NotNull Project project) {
        return detectedProjectVersions.containsKey(project);
    }

    public void clearDetectedProjectVersions() {
        detectedProjectVersions.clear();
    }

    private @NotNull String requireEnvironmentTool(@NotNull PythonEnvInfo environment,
                                                   @NotNull String configuredExecutable) {
        String toolName = executableFileName(configuredExecutable);
        String resolved = ProjectPythonEnvResolver.findTool(environment, toolName);
        if (ZaStrUtil.isBlank(resolved)) {
            throw new PythonEnvResolutionException(String.format(
                    "Frida tool '%s' was not found in Python environment %s. Install frida-tools in that environment.",
                    toolName,
                    environment.getEnvRoot()
            ));
        }
        return resolved;
    }

    public @NotNull GeneralCommandLine buildLsDevicesCommandLineForDiagnostics(@NotNull Project project) {
        return buildLsDevicesCommandLine(project);
    }

    public @NotNull GeneralCommandLine buildPsCommandLineForDiagnostics(@NotNull Project project,
                                                                        @NotNull FridaDevice device,
                                                                        @NotNull FridaProcessScope scope) {
        return buildPsCommandLine(project, device, scope);
    }

    private @NotNull GeneralCommandLine buildLsDevicesCommandLine(@NotNull Project project) {
        ZaFridaSettingsState s = settings.getState();
        GeneralCommandLine cmd = new GeneralCommandLine(s.fridaLsDevicesExecutable)
                .withCharset(StandardCharsets.UTF_8);
        applyProjectPythonEnv(project, cmd);
        return cmd;
    }

    private boolean shouldFallbackToPythonForNoConsole(@NotNull FridaCliException e) {
        if (!SystemInfoRt.isWindows) {
            return false;
        }

        String detail = e.getStderr();
        if (ZaStrUtil.isBlank(detail)) {
            detail = e.getMessage();
        }
        if (ZaStrUtil.isBlank(detail)) {
            return false;
        }

        String lower = detail.toLowerCase(Locale.ROOT);
        if (lower.contains("noconsolescreenbuffererror")) {
            return true;
        }
        if (lower.contains("no windows console found")) {
            return true;
        }
        // prompt_toolkit 在无 Console 的 Windows IDE 子进程中也会触发该错误。
        if (lower.contains("prompt_toolkit") && lower.contains("no console")) {
            return true;
        }
        return false;
    }

    private @NotNull List<FridaDevice> listDevicesViaPython(@NotNull Project project) {
        List<String> candidates = resolvePythonCandidates(project);
        FridaCliException lastCliError = null;

        for (String pythonExe : candidates) {
            try {
                GeneralCommandLine cmd = buildPythonEnumerateDevicesCommandLine(project, pythonExe);
                CapturedOut out = runCapturing(cmd, LIST_DEVICES_TIMEOUT_MS);
                return FridaOutputParsers.parseDevices(out.stdout);
            } catch (FridaCliException e) {
                lastCliError = e;
                LOG.warn(String.format("List devices via python failed: python=%s exit=%s cmd=%s", pythonExe, e.getExitCode(), e.getCommandLine()));
            } catch (ProcessCanceledException canceled) {
                throw canceled;
            } catch (Throwable t) {
                LOG.warn(String.format("List devices via python failed: python=%s", pythonExe), t);
            }
        }

        if (lastCliError != null) {
            throw lastCliError;
        }
        return new ArrayList<>();
    }

    private @NotNull List<String> resolvePythonCandidates(@NotNull Project project) {
        Set<String> out = new LinkedHashSet<>();

        PythonEnvInfo env = ProjectPythonEnvResolver.resolve(project);
        if (env != null) {
            String home = env.getPythonHome();
            if (ZaStrUtil.isNotBlank(home)) {
                out.add(home);
            }
        }

        if (env != null) {
            return new ArrayList<>(out);
        }

        out.add("python");
        if (SystemInfoRt.isWindows) {
            out.add("py");
        }

        return new ArrayList<>(out);
    }

    private @NotNull GeneralCommandLine buildPythonEnumerateDevicesCommandLine(@NotNull Project project,
                                                                              @NotNull String pythonExe) {
        GeneralCommandLine cmd = new GeneralCommandLine(pythonExe)
                .withCharset(StandardCharsets.UTF_8);

        applyProjectPythonEnv(project, cmd);
        cmd.addParameters("-c", PY_ENUM_DEVICES_SCRIPT);
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
            }
            case RUNNING_APPS -> cmd.addParameter("-a");
            case INSTALLED_APPS -> cmd.addParameters("-a", "-i");
        }

        return cmd;
    }

    private void applyProjectPythonEnv(@NotNull Project project, @NotNull GeneralCommandLine cmd) {
        // 保留父进程环境，只把选中 Python 环境的目录前置到 PATH。
        cmd.withParentEnvironmentType(GeneralCommandLine.ParentEnvironmentType.CONSOLE);
        applyPythonOutputEncodingEnv(cmd);
        PythonEnvInfo env = ProjectPythonEnvResolver.resolve(project);
        if (env != null) {
            resolveExecutableFromEnvironment(cmd, env);
            ProjectPythonEnvResolver.applyToCommandLine(cmd, env);
        }
    }

    // 裸命令必须来自已解析的 Python 环境；用户配置的绝对工具路径仍保持原语义。
    private void resolveExecutableFromEnvironment(@NotNull GeneralCommandLine commandLine,
                                                  @NotNull PythonEnvInfo environment) {
        String executable = commandLine.getExePath();
        if (ZaStrUtil.isBlank(executable)) {
            return;
        }

        boolean projectOverride = environment.getSource() == PythonEnvInfo.Source.ZAFRIDA_PROJECT;
        if (!projectOverride && looksLikePath(executable)) {
            return;
        }

        String toolName = executableFileName(executable);
        String resolved = ProjectPythonEnvResolver.findTool(environment, toolName);
        if (ZaStrUtil.isNotBlank(resolved)) {
            commandLine.setExePath(resolved);
            return;
        }
        if (projectOverride || !looksLikePath(executable)) {
            String sourceLabel = "IDE project";
            if (projectOverride) {
                sourceLabel = "selected ZAFrida project";
            }
            throw new PythonEnvResolutionException(String.format(
                    "Frida tool '%s' was not found in the %s Python environment: %s. Install frida-tools in that environment.",
                    toolName,
                    sourceLabel,
                    environment.getEnvRoot()
            ));
        }
    }

    private static @NotNull String executableFileName(@NotNull String executable) {
        try {
            Path fileName = Path.of(executable).getFileName();
            if (fileName != null) {
                return fileName.toString();
            }
        } catch (InvalidPathException e) {
            LOG.debug(String.format("Cannot parse executable path, use original value: %s", executable), e);
        }
        return executable;
    }

    private void applyPythonOutputEncodingEnv(@NotNull GeneralCommandLine cmd) {
        cmd.getEnvironment().put(ENV_PYTHONIOENCODING, "UTF-8");
        cmd.getEnvironment().put(ENV_PYTHONUTF8, "1");
        cmd.getEnvironment().put(ENV_PYTHONUNBUFFERED, "1");
    }

    private static boolean looksLikePath(@NotNull String value) {
        return value.contains("/") || value.contains("\\");
    }

    private void addDeviceArgs(@NotNull GeneralCommandLine cmd, @NotNull FridaDevice device) {
        if (device.getMode() == FridaDeviceMode.HOST) {
            String host = device.getHost();
            if (ZaStrUtil.isBlank(host)) {
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
            throw processStartException(cmd, e);
        }
        ProcessOutput out = handler.runProcess(timeoutMs);

        String stdout = out.getStdout();
        if (stdout == null) {
            stdout = "";
        }
        String stderr = out.getStderr();
        if (stderr == null) {
            stderr = "";
        }
        int exitCode = out.getExitCode();

        if (out.isTimeout()) {
            String commandLine = cmd.getCommandLineString();
            throw new FridaCliException(
                    String.format("Command timed out after %sms: %s", timeoutMs, commandLine),
                    commandLine,
                    exitCode,
                    stdout,
                    stderr,
                    true
            );
        }

        if (exitCode != 0) {
            String cmdLine = cmd.getCommandLineString();
            LOG.warn(String.format("Frida tool failed: exit=%s cmd=%s stderr=%s stdout=%s", exitCode, cmdLine, stderr, stdout));
            throw new FridaCliException(
                    String.format("Command failed (exit=%s): %s\n%s", exitCode, cmdLine, stderr),
                    cmdLine,
                    exitCode,
                    stdout,
                    stderr
            );
        }

        return new CapturedOut(stdout, stderr, exitCode);
    }

    private @NotNull FridaCliException processStartException(@NotNull GeneralCommandLine commandLine,
                                                              @NotNull ExecutionException cause) {
        String command = commandLine.getCommandLineString();
        String detail = cause.getMessage();
        if (ZaStrUtil.isBlank(detail)) {
            detail = cause.getClass().getSimpleName();
        }
        return new FridaCliException(
                String.format("Cannot start Frida command: %s (%s)", command, detail),
                command,
                -1,
                "",
                detail
        );
    }
}
