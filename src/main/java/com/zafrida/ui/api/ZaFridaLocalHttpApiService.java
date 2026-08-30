package com.zafrida.ui.api;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.application.ModalityState;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.LocalFileSystem;
import com.intellij.openapi.vfs.VirtualFile;
import com.zafrida.ui.adb.AdbService;
import com.zafrida.ui.diagnostics.ZaFridaDiagnosticItem;
import com.zafrida.ui.diagnostics.ZaFridaDiagnosticStatus;
import com.zafrida.ui.diagnostics.ZaFridaDiagnosticsListener;
import com.zafrida.ui.diagnostics.ZaFridaDiagnosticsService;
import com.zafrida.ui.frida.FridaCliService;
import com.zafrida.ui.frida.FridaCliException;
import com.zafrida.ui.frida.FridaConnectionMode;
import com.zafrida.ui.frida.FridaDevice;
import com.zafrida.ui.frida.FridaDeviceMode;
import com.zafrida.ui.frida.FridaProcess;
import com.zafrida.ui.frida.FridaProcessScope;
import com.zafrida.ui.fridaproject.ZaFridaFridaProject;
import com.zafrida.ui.fridaproject.ZaFridaPlatform;
import com.zafrida.ui.fridaproject.ZaFridaProjectConfig;
import com.zafrida.ui.fridaproject.ZaFridaProjectManager;
import com.zafrida.ui.logging.ZaFridaLogPaths;
import com.zafrida.ui.python.ProjectPythonEnvResolver;
import com.zafrida.ui.python.PythonEnvInfo;
import com.zafrida.ui.python.PythonEnvResolutionException;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.settings.ZaFridaSettingsState;
import com.zafrida.ui.session.ZaFridaSessionService;
import com.zafrida.ui.session.ZaFridaSessionType;
import com.zafrida.ui.session.RunningSession;
import com.zafrida.ui.ui.ZaFridaConsolePanel;
import com.zafrida.ui.ui.ZaFridaRunPanel;
import com.zafrida.ui.util.ProjectFileUtil;
import com.zafrida.ui.util.ZaFridaNetUtil;
import com.zafrida.ui.util.ZaStrUtil;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public final class ZaFridaLocalHttpApiService implements Disposable {

    private static final Logger LOG = Logger.getInstance(ZaFridaLocalHttpApiService.class);

    private static final String BIND_HOST = "127.0.0.1";
    private static final long DEFAULT_TIMEOUT_SECONDS = 10L;

    private static final String API_BASE = "/zafrida/api/v1";
    private static final String API_HEALTH = API_BASE + "/health";
    private static final String API_CAPABILITIES = API_BASE + "/capabilities";
    private static final String API_STATE = API_BASE + "/state";

    private static final String API_PROJECT_CURRENT = API_BASE + "/project/current";
    private static final String API_PROJECT_SELECT = API_BASE + "/project/select";
    private static final String API_PROJECT_CREATE = API_BASE + "/project/create";
    private static final String API_PROJECT_PYTHON_ENVIRONMENT_SET = API_BASE + "/project/python-environment/set";
    private static final String API_PYTHON_ENVIRONMENT_CURRENT = API_BASE + "/python-environment/current";
    private static final String API_PYTHON_ENVIRONMENT_TEST = API_BASE + "/python-environment/test";

    private static final String API_DEVICE_SELECT = API_BASE + "/device/select";
    private static final String API_CONNECTION_MODE_SET = API_BASE + "/connection-mode/set";
    private static final String API_TARGET_SET = API_BASE + "/target/set";
    private static final String API_RUN_SCRIPT_SET = API_BASE + "/run-script/set";
    private static final String API_ATTACH_SCRIPT_SET = API_BASE + "/attach-script/set";
    private static final String API_EXTRA_ARGS_SET = API_BASE + "/extra-args/set";

    private static final String API_RUN = API_BASE + "/run";
    private static final String API_STOP = API_BASE + "/stop";
    private static final String API_ATTACH = API_BASE + "/attach";
    private static final String API_STOP_ATTACH = API_BASE + "/stop-attach";
    private static final String API_SESSION_STATUS = API_BASE + "/session/status";

    private static final String API_RUN_LOG_PATH = API_BASE + "/run-log/path";
    private static final String API_RUN_LOG_CONTENT = API_BASE + "/run-log/content";
    private static final String API_ATTACH_LOG_PATH = API_BASE + "/attach-log/path";
    private static final String API_ATTACH_LOG_CONTENT = API_BASE + "/attach-log/content";
    private static final String API_RUN_LOG_LINES = API_BASE + "/run-log/lines";
    private static final String API_ATTACH_LOG_LINES = API_BASE + "/attach-log/lines";
    private static final String API_RUN_LOG_TAIL = API_BASE + "/run-log/tail";
    private static final String API_ATTACH_LOG_TAIL = API_BASE + "/attach-log/tail";
    private static final String API_LOGS_LIST = API_BASE + "/logs/list";

    private static final String API_DEVICES = API_BASE + "/devices";
    private static final String API_PROCESSES = API_BASE + "/processes";
    private static final String API_ADB_FORCE_STOP = API_BASE + "/adb/force-stop";
    private static final String API_ADB_OPEN_APP = API_BASE + "/adb/open-app";
    private static final String API_CONSOLE_CLEAR = API_BASE + "/console/clear";
    private static final String API_DIAGNOSTICS = API_BASE + "/diagnostics";

    private static final int MAX_LINES_PER_REQUEST = 2000;
    private static final int DEFAULT_TAIL_BYTES = 64 * 1024;
    private static final int MAX_LOG_RESPONSE_BYTES = 4 * 1024 * 1024;
    private static final int MAX_CONSOLE_SNAPSHOT_CHARACTERS = MAX_LOG_RESPONSE_BYTES;
    private static final int MAX_REQUEST_BODY_BYTES = 64 * 1024;
    private static final int DEFAULT_LOG_LIST_LIMIT = 50;
    private static final int MAX_LOG_LIST_LIMIT = 200;
    private static final int MAX_SERVER_THREADS = 4;
    private static final long DIAGNOSTICS_TIMEOUT_SECONDS = 60L;

    private static final AtomicInteger SERVER_THREAD_ID = new AtomicInteger(1);

    private final @NotNull Project project;
    private final @NotNull ZaFridaProjectManager projectManager;
    private final @NotNull ZaFridaSessionService sessionService;
    private final @NotNull ZaFridaSettingsService settingsService;
    private final @NotNull FridaCliService fridaCliService;
    private final @NotNull AdbService adbService;
    private final @NotNull ZaFridaDiagnosticsService diagnosticsService;

    private final AtomicReference<ZaFridaRunPanel> runPanelRef = new AtomicReference<>();
    private final Object serverLock = new Object();

    private volatile @Nullable HttpServer server;
    private volatile @Nullable ExecutorService serverExecutor;
    private volatile int boundPort = -1;
    private volatile @Nullable String lastStartError;

    public ZaFridaLocalHttpApiService(@NotNull Project project) {
        this.project = project;
        this.projectManager = project.getService(ZaFridaProjectManager.class);
        this.sessionService = project.getService(ZaFridaSessionService.class);
        this.settingsService = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
        this.fridaCliService = ApplicationManager.getApplication().getService(FridaCliService.class);
        this.adbService = ApplicationManager.getApplication().getService(AdbService.class);
        this.diagnosticsService = ApplicationManager.getApplication().getService(ZaFridaDiagnosticsService.class);
        maybeStartBySettingsAsync();
    }

    public void bindRunPanel(@NotNull ZaFridaRunPanel runPanel) {
        runPanelRef.set(runPanel);
    }

    public void unbindRunPanel(@NotNull ZaFridaRunPanel runPanel) {
        runPanelRef.compareAndSet(runPanel, null);
    }

    public int getBoundPort() {
        return boundPort;
    }

    public boolean isServerRunning() {
        return server != null;
    }

    public @Nullable String getLastStartError() {
        return lastStartError;
    }

    public boolean startServerNow() {
        startServerSafely(false, null);
        return server != null;
    }

    public boolean startServerNow(int port) {
        startServerSafely(false, port);
        return server != null;
    }

    public void stopServerNow() {
        stopServerSafely();
    }

    public boolean restartServerNow() {
        stopServerSafely();
        startServerSafely(false, null);
        return server != null;
    }

    public boolean restartServerNow(int port) {
        stopServerSafely();
        startServerSafely(false, port);
        return server != null;
    }

    private void maybeStartBySettingsAsync() {
        ApplicationManager.getApplication().executeOnPooledThread(() -> startServerSafely(true, null));
    }

    private void startServerSafely(boolean requireEnabledInSettings, @Nullable Integer requestedPort) {
        synchronized (serverLock) {
            if (project.isDisposed()) {
                return;
            }
            if (server != null) {
                return;
            }

            if (requireEnabledInSettings && !isEnabledInSettings()) {
                boundPort = -1;
                lastStartError = null;
                return;
            }

            int configuredPort = resolveConfiguredPort(requestedPort);
            InetSocketAddress address = new InetSocketAddress(BIND_HOST, configuredPort);

            HttpServer createdServer;
            try {
                createdServer = HttpServer.create(address, 0);
            } catch (IOException e) {
                lastStartError = String.format("Bind failed on %s:%s (%s)", BIND_HOST, configuredPort, e.getMessage());
                LOG.warn(String.format("[ZAFrida API] Failed to bind %s:%s", BIND_HOST, configuredPort), e);
                return;
            }

            registerContexts(createdServer);

            ExecutorService executor = Executors.newFixedThreadPool(MAX_SERVER_THREADS, new ThreadFactory() {
                @Override
                public Thread newThread(@NotNull Runnable runnable) {
                    Thread thread = new Thread(runnable,
                            String.format("ZAFrida-LocalApi-%s", SERVER_THREAD_ID.getAndIncrement()));
                    thread.setDaemon(true);
                    return thread;
                }
            });
            createdServer.setExecutor(executor);

            createdServer.start();
            server = createdServer;
            serverExecutor = executor;
            boundPort = createdServer.getAddress().getPort();
            lastStartError = null;

            LOG.info(String.format(
                    "[ZAFrida API] Started on http://%s:%s%s",
                    BIND_HOST,
                    boundPort,
                    API_BASE
            ));
        }
    }

    private void stopServerSafely() {
        synchronized (serverLock) {
            HttpServer current = server;
            if (current != null) {
                current.stop(0);
                server = null;
            }
            ExecutorService executor = serverExecutor;
            if (executor != null) {
                executor.shutdownNow();
                serverExecutor = null;
            }
            boundPort = -1;
            lastStartError = null;
        }
    }

    private boolean isEnabledInSettings() {
        ZaFridaSettingsState state = settingsService.getState();
        return state.enableSkillsHttpApi;
    }

    private int resolveConfiguredPort(@Nullable Integer requestedPort) {
        if (requestedPort != null && requestedPort > 0 && requestedPort <= 65_535) {
            return requestedPort;
        }
        ZaFridaSettingsState state = settingsService.getState();
        int configuredPort = state.skillsApiPort;
        if (configuredPort > 0 && configuredPort <= 65535) {
            return configuredPort;
        }
        return ZaFridaSettingsState.DEFAULT_SKILLS_API_PORT;
    }

    private void registerContexts(@NotNull HttpServer createdServer) {
        createdServer.createContext(API_HEALTH, exchange -> dispatch(exchange, "GET", this::handleHealth));
        createdServer.createContext(API_CAPABILITIES, exchange -> dispatch(exchange, "GET", this::handleCapabilities));
        createdServer.createContext(API_STATE, exchange -> dispatch(exchange, "GET", this::handleState));

        createdServer.createContext(API_PROJECT_CURRENT, exchange -> dispatch(exchange, "GET", this::handleProjectCurrent));
        createdServer.createContext(API_PROJECT_SELECT, exchange -> dispatch(exchange, "POST", this::handleProjectSelect));
        createdServer.createContext(API_PROJECT_CREATE, exchange -> dispatch(exchange, "POST", this::handleProjectCreate));
        createdServer.createContext(API_PROJECT_PYTHON_ENVIRONMENT_SET,
                exchange -> dispatch(exchange, "POST", this::handleProjectPythonEnvironmentSet));
        createdServer.createContext(API_PYTHON_ENVIRONMENT_CURRENT,
                exchange -> dispatch(exchange, "GET", this::handlePythonEnvironmentCurrent));
        createdServer.createContext(API_PYTHON_ENVIRONMENT_TEST,
                exchange -> dispatch(exchange, "POST", this::handlePythonEnvironmentTest));

        createdServer.createContext(API_DEVICE_SELECT, exchange -> dispatch(exchange, "POST", this::handleDeviceSelect));
        createdServer.createContext(API_CONNECTION_MODE_SET, exchange -> dispatch(exchange, "POST", this::handleConnectionModeSet));
        createdServer.createContext(API_TARGET_SET, exchange -> dispatch(exchange, "POST", this::handleTargetSet));
        createdServer.createContext(API_RUN_SCRIPT_SET, exchange -> dispatch(exchange, "POST", this::handleRunScriptSet));
        createdServer.createContext(API_ATTACH_SCRIPT_SET, exchange -> dispatch(exchange, "POST", this::handleAttachScriptSet));
        createdServer.createContext(API_EXTRA_ARGS_SET, exchange -> dispatch(exchange, "POST", this::handleExtraArgsSet));

        createdServer.createContext(API_RUN, exchange -> dispatch(exchange, "POST", this::handleRun));
        createdServer.createContext(API_STOP, exchange -> dispatch(exchange, "POST", this::handleStop));
        createdServer.createContext(API_ATTACH, exchange -> dispatch(exchange, "POST", this::handleAttach));
        createdServer.createContext(API_STOP_ATTACH, exchange -> dispatch(exchange, "POST", this::handleStopAttach));
        createdServer.createContext(API_SESSION_STATUS, exchange -> dispatch(exchange, "GET", this::handleSessionStatus));

        createdServer.createContext(API_RUN_LOG_PATH, exchange -> dispatch(exchange, "GET", this::handleRunLogPath));
        createdServer.createContext(API_RUN_LOG_CONTENT, exchange -> dispatch(exchange, "GET", this::handleRunLogContent));
        createdServer.createContext(API_ATTACH_LOG_PATH, exchange -> dispatch(exchange, "GET", this::handleAttachLogPath));
        createdServer.createContext(API_ATTACH_LOG_CONTENT, exchange -> dispatch(exchange, "GET", this::handleAttachLogContent));
        createdServer.createContext(API_RUN_LOG_LINES, exchange -> dispatch(exchange, "GET", this::handleRunLogLines));
        createdServer.createContext(API_ATTACH_LOG_LINES, exchange -> dispatch(exchange, "GET", this::handleAttachLogLines));
        createdServer.createContext(API_RUN_LOG_TAIL, exchange -> dispatch(exchange, "GET", this::handleRunLogTail));
        createdServer.createContext(API_ATTACH_LOG_TAIL, exchange -> dispatch(exchange, "GET", this::handleAttachLogTail));
        createdServer.createContext(API_LOGS_LIST, exchange -> dispatch(exchange, "GET", this::handleLogsList));

        createdServer.createContext(API_DEVICES, exchange -> dispatch(exchange, "GET", this::handleDevices));
        createdServer.createContext(API_PROCESSES, exchange -> dispatch(exchange, "GET", this::handleProcesses));
        createdServer.createContext(API_ADB_FORCE_STOP, exchange -> dispatch(exchange, "POST", this::handleAdbForceStop));
        createdServer.createContext(API_ADB_OPEN_APP, exchange -> dispatch(exchange, "POST", this::handleAdbOpenApp));
        createdServer.createContext(API_CONSOLE_CLEAR, exchange -> dispatch(exchange, "POST", this::handleConsoleClear));
        createdServer.createContext(API_DIAGNOSTICS, exchange -> dispatch(exchange, "GET", this::handleDiagnostics));
    }

    private void dispatch(@NotNull HttpExchange exchange,
                          @NotNull String requiredMethod,
                          @NotNull ApiHandler handler) throws IOException {
        try {
            validateRequestOrigin(exchange);
            String registeredPath = exchange.getHttpContext().getPath();
            String requestedPath = exchange.getRequestURI().getPath();
            if (!registeredPath.equals(requestedPath)) {
                throw new ApiException(404, String.format("Unknown API path: %s", requestedPath));
            }
            String requestMethod = exchange.getRequestMethod();
            if ("OPTIONS".equalsIgnoreCase(requestMethod)) {
                writeNoContent(exchange);
                return;
            }

            if (!requiredMethod.equalsIgnoreCase(requestMethod)) {
                throw new ApiException(405, String.format("Method not allowed: %s", requestMethod));
            }

            RequestContext request = RequestContext.from(exchange);
            Map<String, Object> data = handler.handle(request);
            writeSuccess(exchange, data);
        } catch (ApiException e) {
            writeError(exchange, e.statusCode, e.errorCode, e.retryable, e.getMessage());
        } catch (PythonEnvResolutionException e) {
            writeError(exchange, 422, "PYTHON_ENVIRONMENT_INVALID", false, safeErrorMessage(e));
        } catch (FridaCliException e) {
            ApiException apiException = mapFridaFailure(e);
            writeError(exchange,
                    apiException.statusCode,
                    apiException.errorCode,
                    apiException.retryable,
                    apiException.getMessage());
        } catch (Throwable t) {
            LOG.warn("[ZAFrida API] Request handling failed", t);
            String message = t.getMessage();
            if (ZaStrUtil.isBlank(message)) {
                message = t.getClass().getSimpleName();
            }
            writeError(exchange, 500, "INTERNAL_ERROR", false, String.format("Internal error: %s", message));
        } finally {
            exchange.close();
        }
    }

    private @NotNull Map<String, Object> handleHealth(@NotNull RequestContext request) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("status", "ok");
        data.put("host", BIND_HOST);
        data.put("port", boundPort);
        data.put("basePath", API_BASE);
        data.put("runPanelReady", runPanelRef.get() != null);
        return data;
    }

    private @NotNull Map<String, Object> handleCapabilities(@NotNull RequestContext request) {
        Map<String, Object> limits = new LinkedHashMap<>();
        limits.put("maxLogResponseBytes", MAX_LOG_RESPONSE_BYTES);
        limits.put("maxLogLinesPerRequest", MAX_LINES_PER_REQUEST);
        limits.put("maxLogFilesPerRequest", MAX_LOG_LIST_LIMIT);
        limits.put("maxRequestBodyBytes", MAX_REQUEST_BODY_BYTES);

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("apiVersion", "v1");
        data.put("apiRevision", 2);
        data.put("scriptExtensions", List.of("js", "ts"));
        data.put("features", List.of(
                "project-python-environments",
                "shared-python-environments",
                "frida-17-typescript",
                "session-status",
                "historical-log-list",
                "incremental-log-tail"
        ));
        data.put("safeAutomaticRetries", List.of(
                "health", "capabilities", "state", "session-status", "diagnostics",
                "project-current", "python-environment-current", "python-environment-test",
                "devices", "processes", "logs-list", "log-path", "log-content", "log-lines", "log-tail"
        ));
        data.put("nonIdempotentActions", List.of("project-create", "run", "attach", "adb-open-app"));
        data.put("mutationsNotAutomaticallyRetried", List.of(
                "project-select", "project-create", "python-environment-set", "device-select",
                "connection-mode-set", "target-set", "run-script-set", "attach-script-set", "extra-args-set",
                "run", "attach", "adb-force-stop", "adb-open-app"
        ));
        data.put("limits", limits);
        return data;
    }

    private @NotNull Map<String, Object> handleState(@NotNull RequestContext request) throws Exception {
        return buildStateSummary();
    }

    private @NotNull Map<String, Object> handleProjectCurrent(@NotNull RequestContext request) throws Exception {
        ZaFridaFridaProject active = projectManager.getActiveProject();
        ZaFridaProjectConfig cfg = loadProjectConfigBlocking(active);

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("activeProject", projectToMap(active));
        data.put("projects", projectListToMap(projectManager.listProjects()));
        data.put("config", configToMap(cfg));
        return data;
    }

    private @NotNull Map<String, Object> handleProjectSelect(@NotNull RequestContext request) throws Exception {
        String projectName = request.require("name");
        ZaFridaFridaProject targetProject = findProjectByName(projectName);
        if (targetProject == null) {
            throw new ApiException(404, String.format("Project not found: %s", projectName));
        }

        CompletableFuture<Void> future = new CompletableFuture<>();
        projectManager.setActiveProjectAsync(targetProject, () -> future.complete(null));
        awaitVoidFuture(future, "Switch project timeout");

        ZaFridaRunPanel panel = runPanelRef.get();
        if (panel != null) {
            runOnUiThreadAndWait(panel::refreshActiveProjectUiForApi);
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("activeProject", projectToMap(targetProject));
        return data;
    }

    private @NotNull Map<String, Object> handleProjectCreate(@NotNull RequestContext request) throws Exception {
        String name = request.require("name");
        if (".".equals(name.trim()) || "..".equals(name.trim())) {
            throw new ApiException(400, "Project name cannot be '.' or '..'");
        }
        String platformRaw = request.getOrDefault("platform", "android");
        ZaFridaPlatform platform = parsePlatform(platformRaw);

        CompletableFuture<ZaFridaFridaProject> future = new CompletableFuture<>();
        projectManager.createAndActivateAsync(name, platform, future::complete, future::completeExceptionally);
        ZaFridaFridaProject created = waitFuture(future, "Create project timeout");

        ZaFridaRunPanel panel = runPanelRef.get();
        if (panel != null) {
            runOnUiThreadAndWait(panel::refreshActiveProjectUiForApi);
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("activeProject", projectToMap(created));
        return data;
    }

    private @NotNull Map<String, Object> handleProjectPythonEnvironmentSet(@NotNull RequestContext request) throws Exception {
        ZaFridaFridaProject activeProject = requireActiveProject();
        String configuredPath = request.getOrDefault("path", "").trim();
        if (!configuredPath.isEmpty()) {
            ProjectPythonEnvResolver.resolveConfiguredPath(configuredPath);
        }

        CompletableFuture<Void> future = new CompletableFuture<>();
        projectManager.updateProjectConfigAsync(activeProject,
                config -> config.pythonEnvironmentPath = configuredPath,
                () -> future.complete(null),
                future::completeExceptionally);
        awaitVoidFuture(future, "Update Python environment timeout");
        fridaCliService.clearDetectedProjectVersion(project);

        ZaFridaRunPanel panel = runPanelRef.get();
        if (panel != null) {
            runOnUiThreadAndWait(panel::refreshActiveProjectUiForApi);
        }

        PythonEnvInfo environment = ProjectPythonEnvResolver.resolve(project);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("configuredPath", configuredPath);
        data.put("usesIdeProjectInterpreter", configuredPath.isEmpty());
        data.put("environment", environmentToMap(environment));
        return data;
    }

    private @NotNull Map<String, Object> handlePythonEnvironmentCurrent(@NotNull RequestContext request) {
        PythonEnvInfo environment = ProjectPythonEnvResolver.resolve(project);
        Map<String, Object> data = new LinkedHashMap<>();
        String configuredPath = projectManager.getActivePythonEnvironmentPath();
        data.put("configuredPath", configuredPath);
        data.put("usesIdeProjectInterpreter", configuredPath.isEmpty());
        data.put("environment", environmentToMap(environment));
        return data;
    }

    private @NotNull Map<String, Object> handlePythonEnvironmentTest(@NotNull RequestContext request) {
        String candidatePath = request.get("path");
        PythonEnvInfo environment;
        String version;
        if (ZaStrUtil.isBlank(candidatePath)) {
            environment = ProjectPythonEnvResolver.resolve(project);
            if (environment == null) {
                throw new ApiException(422, "PYTHON_ENVIRONMENT_NOT_FOUND", false,
                        "The effective project Python environment could not be resolved");
            }
            version = fridaCliService.detectProjectFridaVersion(project);
        } else {
            environment = ProjectPythonEnvResolver.resolveConfiguredPath(candidatePath);
            version = fridaCliService.detectFridaPythonVersion(environment);
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("environment", environmentToMap(environment));
        data.put("fridaVersion", version);
        data.put("frida17OrLater", ZaStrUtil.compareVersion(version, "17") >= 0);
        data.put("typescriptDirectLoad", ZaStrUtil.compareVersion(version, "17") >= 0);
        return data;
    }

    private @NotNull Map<String, Object> handleDeviceSelect(@NotNull RequestContext request) throws Exception {
        String id = request.get("id");
        String host = request.get("host");
        if (ZaStrUtil.isBlank(id) && ZaStrUtil.isBlank(host)) {
            throw new ApiException(400, "Missing parameter: id or host");
        }

        ZaFridaRunPanel panel = requireRunPanel();
        boolean selected = callOnUiThreadAndWait(() -> {
            boolean matched = false;
            if (ZaStrUtil.isNotBlank(id)) {
                matched = panel.selectDeviceByIdForApi(id);
            }
            if (!matched && ZaStrUtil.isNotBlank(host)) {
                matched = panel.selectDeviceByHostForApi(host);
            }
            return matched;
        });
        if (!selected) {
            FridaDevice discovered = findRequestedDevice(listAvailableDevices(), id, host);
            if (discovered == null && ZaStrUtil.isNotBlank(host)) {
                String normalizedHost = host.trim();
                discovered = new FridaDevice(
                        String.format("remote:%s", normalizedHost),
                        "remote",
                        "Remote",
                        FridaDeviceMode.HOST,
                        normalizedHost
                );
            }
            if (discovered == null) {
                throw new ApiException(404, "Device not found");
            }
            FridaDevice finalDiscovered = discovered;
            runOnUiThreadAndWait(() -> panel.selectDeviceForApi(finalDiscovered));
        }

        FridaDevice selectedDevice = callOnUiThreadAndWait(panel::getSelectedDeviceForApi);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("device", deviceToMap(selectedDevice));
        return data;
    }

    private @NotNull Map<String, Object> handleConnectionModeSet(@NotNull RequestContext request) throws Exception {
        String modeText = request.require("mode");
        FridaConnectionMode mode = parseConnectionMode(modeText);

        ZaFridaFridaProject activeProject = requireActiveProject();
        String host = request.get("host");
        Integer port = parseOptionalPort(request.get("port"));

        CompletableFuture<Void> future = new CompletableFuture<>();
        projectManager.updateProjectConfigAsync(activeProject, cfg -> {
            cfg.connectionMode = mode;
            if (mode == FridaConnectionMode.USB) {
                cfg.lastDeviceHost = null;
                return;
            }

            if (ZaStrUtil.isNotBlank(host)) {
                cfg.remoteHost = host.trim();
            }
            if (port != null) {
                cfg.remotePort = port;
            }

            cfg.remoteHost = ZaFridaNetUtil.defaultHost(cfg.remoteHost);
            cfg.remotePort = ZaFridaNetUtil.defaultPort(cfg.remotePort);
            cfg.lastDeviceHost = String.format("%s:%s", cfg.remoteHost, cfg.remotePort);
        }, () -> future.complete(null));
        awaitVoidFuture(future, "Update connection mode timeout");

        ZaFridaRunPanel panel = runPanelRef.get();
        if (panel != null) {
            runOnUiThreadAndWait(panel::refreshActiveProjectUiForApi);
        }

        ZaFridaProjectConfig cfg = loadProjectConfigBlocking(activeProject);

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("mode", mode.name().toLowerCase(Locale.ROOT));
        data.put("config", configToMap(cfg));
        return data;
    }

    private @NotNull Map<String, Object> handleTargetSet(@NotNull RequestContext request) throws Exception {
        String target = request.getOrDefault("target", "");
        ZaFridaRunPanel panel = requireRunPanel();
        runOnUiThreadAndWait(() -> panel.setTargetTextForApi(target));

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("target", target.trim());
        return data;
    }

    private @NotNull Map<String, Object> handleRunScriptSet(@NotNull RequestContext request) throws Exception {
        String path = request.require("path");
        ZaFridaRunPanel panel = requireRunPanel();
        VirtualFile file = resolveFridaScriptFile(path, "run");
        runOnUiThreadAndWait(() -> panel.setRunScriptFileForApi(file));

        String runScript = callOnUiThreadAndWait(panel::getRunScriptPathForApi);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("runScript", runScript);
        return data;
    }

    private @NotNull Map<String, Object> handleAttachScriptSet(@NotNull RequestContext request) throws Exception {
        String path = request.require("path");
        ZaFridaRunPanel panel = requireRunPanel();
        VirtualFile file = resolveFridaScriptFile(path, "attach");
        runOnUiThreadAndWait(() -> panel.setAttachScriptFileForApi(file));

        String attachScript = callOnUiThreadAndWait(panel::getAttachScriptPathForApi);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("attachScript", attachScript);
        return data;
    }

    private @NotNull Map<String, Object> handleExtraArgsSet(@NotNull RequestContext request) throws Exception {
        String value = request.get("value");
        if (value == null) {
            value = request.getOrDefault("args", "");
        }

        ZaFridaRunPanel panel = requireRunPanel();
        String finalValue = value;
        runOnUiThreadAndWait(() -> panel.setExtraArgsForApi(finalValue));

        String extra = callOnUiThreadAndWait(panel::getExtraArgsForApi);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("extraArgs", extra);
        return data;
    }

    private @NotNull Map<String, Object> handleRun(@NotNull RequestContext request) throws Exception {
        ZaFridaRunPanel panel = requireRunPanel();
        runOnUiThreadAndWait(panel::triggerRun);
        return actionResult("run");
    }

    private @NotNull Map<String, Object> handleStop(@NotNull RequestContext request) throws Exception {
        ZaFridaRunPanel panel = requireRunPanel();
        runOnUiThreadAndWait(panel::triggerStop);
        return actionResult("stop");
    }

    private @NotNull Map<String, Object> handleAttach(@NotNull RequestContext request) throws Exception {
        ZaFridaRunPanel panel = requireRunPanel();
        runOnUiThreadAndWait(panel::triggerAttach);
        return actionResult("attach");
    }

    private @NotNull Map<String, Object> handleStopAttach(@NotNull RequestContext request) throws Exception {
        ZaFridaRunPanel panel = requireRunPanel();
        runOnUiThreadAndWait(panel::triggerStopAttach);
        return actionResult("stop-attach");
    }

    private @NotNull Map<String, Object> handleSessionStatus(@NotNull RequestContext request) throws Exception {
        UiSnapshot snapshot = captureUiSnapshot();
        Map<String, Object> run = buildSessionStatus(
                ZaFridaSessionType.RUN,
                snapshot.runLogPath
        );
        Map<String, Object> attach = buildSessionStatus(
                ZaFridaSessionType.ATTACH,
                snapshot.attachLogPath
        );

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("run", run);
        data.put("attach", attach);
        data.put("recommendedPollIntervalMs", 500);
        return data;
    }

    private @NotNull Map<String, Object> handleRunLogPath(@NotNull RequestContext request) throws Exception {
        LogState state = captureLogState(true, false);
        long fileSize = computeFileSize(state.path, state.existsOnDisk);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("path", state.path);
        data.put("exists", state.existsOnDisk);
        data.put("fileSize", fileSize);
        data.put("sizeHuman", formatFileSize(fileSize));
        return data;
    }

    private @NotNull Map<String, Object> handleRunLogContent(@NotNull RequestContext request) throws Exception {
        return readLogContent(true, request);
    }

    private @NotNull Map<String, Object> handleAttachLogPath(@NotNull RequestContext request) throws Exception {
        LogState state = captureLogState(false, false);
        long fileSize = computeFileSize(state.path, state.existsOnDisk);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("path", state.path);
        data.put("exists", state.existsOnDisk);
        data.put("fileSize", fileSize);
        data.put("sizeHuman", formatFileSize(fileSize));
        return data;
    }

    private @NotNull Map<String, Object> handleAttachLogContent(@NotNull RequestContext request) throws Exception {
        return readLogContent(false, request);
    }

    private @NotNull Map<String, Object> handleRunLogLines(@NotNull RequestContext request) throws Exception {
        return readLogLines(true, request);
    }

    private @NotNull Map<String, Object> handleAttachLogLines(@NotNull RequestContext request) throws Exception {
        return readLogLines(false, request);
    }

    private @NotNull Map<String, Object> handleRunLogTail(@NotNull RequestContext request) throws Exception {
        return readLogTail(true, request);
    }

    private @NotNull Map<String, Object> handleAttachLogTail(@NotNull RequestContext request) throws Exception {
        return readLogTail(false, request);
    }

    private @NotNull Map<String, Object> handleLogsList(@NotNull RequestContext request) {
        String type = request.getOrDefault("type", "all").trim().toLowerCase(Locale.ROOT);
        if (!"all".equals(type) && !"run".equals(type) && !"attach".equals(type)) {
            throw new ApiException(400, String.format("Unsupported log type: %s", type));
        }
        int limit = parseNonNegativeInt(request.get("limit"), DEFAULT_LOG_LIST_LIMIT, "limit");
        if (limit <= 0) {
            limit = DEFAULT_LOG_LIST_LIMIT;
        }
        if (limit > MAX_LOG_LIST_LIMIT) {
            limit = MAX_LOG_LIST_LIMIT;
        }

        List<Path> files = new ArrayList<>();
        for (Path root : resolveAllowedLogRoots()) {
            if (!Files.isDirectory(root)) {
                continue;
            }
            try (java.util.stream.Stream<Path> stream = Files.list(root)) {
                stream.filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
                        .filter(path -> path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".log"))
                        .filter(path -> matchesLogType(path, type))
                        .forEach(files::add);
            } catch (IOException e) {
                LOG.debug(String.format("[ZAFrida API] List logs failed: %s", root), e);
            }
        }
        files.sort(Comparator.comparingLong(this::lastModifiedMillis).reversed());

        List<Map<String, Object>> entries = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        for (Path file : files) {
            if (entries.size() >= limit) {
                break;
            }
            String absolutePath = file.toAbsolutePath().normalize().toString();
            if (!seen.add(absolutePath)) {
                continue;
            }
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("path", absolutePath);
            entry.put("name", file.getFileName().toString());
            long size = computeFileSize(absolutePath);
            entry.put("fileSize", size);
            entry.put("sizeHuman", formatFileSize(size));
            entry.put("lastModified", lastModifiedMillis(file));
            entry.put("sessionType", detectLogType(file));
            entries.add(entry);
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("type", type);
        data.put("count", entries.size());
        data.put("logs", entries);
        return data;
    }

    private @NotNull Map<String, Object> readLogContent(boolean runLog, @NotNull RequestContext request) throws Exception {
        LogState state = captureLogState(runLog, true);
        String pathFromParam = request.get("path");
        String normalizedPath = pathFromParam;
        if (ZaStrUtil.isBlank(normalizedPath)) {
            normalizedPath = state.path;
        }
        if (normalizedPath == null) {
            normalizedPath = "";
        }
        normalizedPath = normalizedPath.trim();

        int maxBytes = parseNonNegativeInt(request.get("maxBytes"), 0, "maxBytes");
        if (maxBytes > MAX_LOG_RESPONSE_BYTES) {
            throw new ApiException(400, String.format(
                    "maxBytes exceeds the server limit (%s): %s",
                    MAX_LOG_RESPONSE_BYTES,
                    maxBytes
            ));
        }

        if (normalizedPath.isEmpty() || normalizedPath.startsWith("(")) {
            int consoleLimit = MAX_LOG_RESPONSE_BYTES;
            if (maxBytes > 0) {
                consoleLimit = maxBytes;
            }
            byte[] consoleBytes = state.consoleText.getBytes(StandardCharsets.UTF_8);
            ByteChunk consoleChunk = readUtf8Tail(consoleBytes, consoleLimit);
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("path", normalizedPath);
            data.put("source", "console");
            data.put("content", new String(consoleChunk.bytes, StandardCharsets.UTF_8));
            data.put("truncated", state.consoleTruncated || consoleChunk.startOffset > 0L);
            return data;
        }

        Path logPath = resolveReadableLogFile(normalizedPath);
        return readLogFileContent(logPath, maxBytes);
    }

    private @NotNull LogState captureLogState(boolean runLog, boolean includeConsole) throws Exception {
        ZaFridaRunPanel panel = runPanelRef.get();
        if (panel == null) {
            return new LogState("", "", false, false);
        }
        LogState snapshot = callOnUiThreadAndWait(() -> {
            ZaFridaConsolePanel console;
            if (runLog) {
                console = panel.getRunConsolePanelForApi();
            } else {
                console = panel.getAttachConsolePanelForApi();
            }

            String path = console.getLogFilePath();
            if (path == null) {
                path = "";
            }
            String trimmedPath = path.trim();
            String consoleText = "";
            boolean consoleTruncated = false;
            if (includeConsole && (trimmedPath.isEmpty() || trimmedPath.startsWith("("))) {
                int consoleLength = console.getConsoleTextLength();
                consoleText = console.getConsoleTextTailSnapshot(MAX_CONSOLE_SNAPSHOT_CHARACTERS);
                consoleTruncated = consoleLength > MAX_CONSOLE_SNAPSHOT_CHARACTERS;
            }
            return new LogState(trimmedPath, consoleText, false, consoleTruncated);
        });
        boolean exists = false;
        if (!snapshot.path.isEmpty() && !snapshot.path.startsWith("(")) {
            try {
                Path filePath = Paths.get(snapshot.path);
                exists = Files.isRegularFile(filePath);
            } catch (RuntimeException e) {
                LOG.debug(String.format("[ZAFrida API] Invalid current log path: %s", snapshot.path), e);
            }
        }
        return new LogState(snapshot.path, snapshot.consoleText, exists, snapshot.consoleTruncated);
    }

    private @NotNull Map<String, Object> readLogFileContent(@NotNull Path logPath, int maxBytes) throws IOException {
        long fileSize = Files.size(logPath);
        boolean truncated = false;
        byte[] bytes;

        if (maxBytes > 0 && fileSize > maxBytes) {
            truncated = true;
            bytes = readTailBytes(logPath, maxBytes);
        } else {
            if (fileSize > MAX_LOG_RESPONSE_BYTES) {
                throw new ApiException(
                        413,
                        "LOG_RESPONSE_TOO_LARGE",
                        false,
                        String.format("Log is %s bytes; use /tail or maxBytes <= %s", fileSize, MAX_LOG_RESPONSE_BYTES)
                );
            }
            bytes = Files.readAllBytes(logPath);
        }

        String content = new String(bytes, StandardCharsets.UTF_8);

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("path", logPath.toAbsolutePath().toString());
        data.put("source", "file");
        data.put("content", content);
        data.put("truncated", truncated);
        data.put("fileSize", fileSize);
        data.put("sizeHuman", formatFileSize(fileSize));
        if (maxBytes > 0) {
            data.put("maxBytes", maxBytes);
        }
        return data;
    }

    private byte @NotNull [] readTailBytes(@NotNull Path path, int maxBytes) throws IOException {
        long length = Files.size(path);
        long start = Math.max(0L, length - maxBytes);
        return readUtf8Chunk(path, start, maxBytes, length).bytes;
    }

    private @NotNull Map<String, Object> readLogLines(boolean runLog, @NotNull RequestContext request) throws Exception {
        LogState state = captureLogState(runLog, false);
        String path = request.get("path");
        if (ZaStrUtil.isBlank(path)) {
            path = state.path;
        }
        if (path == null) {
            path = "";
        }
        path = path.trim();

        if (path.isEmpty() || path.startsWith("(")) {
            throw new ApiException(400, "日志文件路径无效，当前会话可能仅使用 Console 输出");
        }

        Path logPath = resolveReadableLogFile(path);

        int startLine = parseNonNegativeInt(request.get("start"), 1, "start");
        if (startLine < 1) {
            startLine = 1;
        }
        int count = parseNonNegativeInt(request.get("count"), 100, "count");
        if (count <= 0) {
            count = 100;
        }
        if (count > MAX_LINES_PER_REQUEST) {
            count = MAX_LINES_PER_REQUEST;
        }

        long fileSize = Files.size(logPath);
        List<String> lines = new ArrayList<>();
        int currentLine = 0;
        int endLine = startLine + count - 1;
        boolean hasMore = false;

        try (BufferedReader reader = Files.newBufferedReader(logPath, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                currentLine++;
                if (currentLine < startLine) {
                    continue;
                }
                if (currentLine > endLine) {
                    hasMore = true;
                    break;
                }
                lines.add(line);
            }
        }

        int actualEndLine = startLine + lines.size() - 1;
        if (lines.isEmpty()) {
            actualEndLine = startLine;
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("path", logPath.toAbsolutePath().toString());
        data.put("fileSize", fileSize);
        data.put("sizeHuman", formatFileSize(fileSize));
        data.put("startLine", startLine);
        data.put("endLine", actualEndLine);
        data.put("linesRead", lines.size());
        data.put("hasMore", hasMore);
        data.put("lines", lines);
        return data;
    }

    private @NotNull Map<String, Object> readLogTail(boolean runLog,
                                                     @NotNull RequestContext request) throws Exception {
        LogState state = captureLogState(runLog, true);
        String path = request.get("path");
        if (ZaStrUtil.isBlank(path)) {
            path = state.path;
        }
        int maxBytes = parseNonNegativeInt(request.get("maxBytes"), DEFAULT_TAIL_BYTES, "maxBytes");
        if (maxBytes <= 0) {
            maxBytes = DEFAULT_TAIL_BYTES;
        }
        if (maxBytes < 4) {
            throw new ApiException(400, "maxBytes must be at least 4 for UTF-8 log reads");
        }
        if (maxBytes > MAX_LOG_RESPONSE_BYTES) {
            throw new ApiException(400, String.format(
                    "maxBytes exceeds the server limit (%s): %s",
                    MAX_LOG_RESPONSE_BYTES,
                    maxBytes
            ));
        }

        if (ZaStrUtil.isBlank(path) || path.trim().startsWith("(")) {
            byte[] consoleBytes = state.consoleText.getBytes(StandardCharsets.UTF_8);
            ByteChunk consoleChunk = readUtf8Tail(consoleBytes, maxBytes);
            Map<String, Object> data = new LinkedHashMap<>();
            String normalizedPath = "";
            if (path != null) {
                normalizedPath = path.trim();
            }
            data.put("path", normalizedPath);
            data.put("source", "console");
            data.put("content", new String(consoleChunk.bytes, StandardCharsets.UTF_8));
            data.put("startOffset", consoleChunk.startOffset);
            data.put("nextOffset", consoleBytes.length);
            data.put("fileSize", consoleBytes.length);
            data.put("hasMore", false);
            data.put("reset", state.consoleTruncated);
            data.put("truncated", state.consoleTruncated || consoleChunk.startOffset > 0L);
            return data;
        }

        Path logPath = resolveReadableLogFile(path);
        long fileSize = Files.size(logPath);
        String offsetText = request.get("offset");
        boolean offsetProvided = ZaStrUtil.isNotBlank(offsetText);
        long startOffset;
        boolean reset = false;
        if (offsetProvided) {
            startOffset = parseNonNegativeLong(offsetText, 0L, "offset");
            if (startOffset > fileSize) {
                startOffset = 0L;
                reset = true;
            }
        } else {
            startOffset = Math.max(0L, fileSize - maxBytes);
        }

        ByteChunk chunk = readUtf8Chunk(logPath, startOffset, maxBytes, fileSize);
        byte[] bytes = chunk.bytes;
        startOffset = chunk.startOffset;
        long nextOffset = startOffset + bytes.length;

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("path", logPath.toAbsolutePath().normalize().toString());
        data.put("source", "file");
        data.put("content", new String(bytes, StandardCharsets.UTF_8));
        data.put("startOffset", startOffset);
        data.put("nextOffset", nextOffset);
        data.put("fileSize", fileSize);
        data.put("sizeHuman", formatFileSize(fileSize));
        data.put("hasMore", nextOffset < fileSize);
        data.put("reset", reset);
        data.put("fromEnd", !offsetProvided);
        return data;
    }

    private @NotNull ByteChunk readUtf8Chunk(@NotNull Path path,
                                             long requestedOffset,
                                             int maxBytes,
                                             long fileSize) throws IOException {
        long startOffset = requestedOffset;
        try (RandomAccessFile file = new RandomAccessFile(path.toFile(), "r")) {
            if (startOffset > 0L && startOffset < fileSize) {
                file.seek(startOffset);
                int first = file.read();
                while (first >= 0 && (first & 0xC0) == 0x80) {
                    startOffset++;
                    first = file.read();
                }
            }
            int count = (int) Math.min((long) maxBytes, Math.max(0L, fileSize - startOffset));
            if (count <= 0) {
                return new ByteChunk(startOffset, new byte[0]);
            }
            file.seek(startOffset);
            byte[] bytes = new byte[count];
            file.readFully(bytes);
            int validLength = completeUtf8PrefixLength(bytes);
            if (validLength == bytes.length) {
                return new ByteChunk(startOffset, bytes);
            }
            byte[] completeBytes = new byte[validLength];
            System.arraycopy(bytes, 0, completeBytes, 0, validLength);
            return new ByteChunk(startOffset, completeBytes);
        }
    }

    private @NotNull ByteChunk readUtf8Tail(byte @NotNull [] bytes, int maxBytes) {
        int start = Math.max(0, bytes.length - maxBytes);
        while (start < bytes.length && (bytes[start] & 0xC0) == 0x80) {
            start++;
        }
        byte[] tail = new byte[bytes.length - start];
        System.arraycopy(bytes, start, tail, 0, tail.length);
        return new ByteChunk(start, tail);
    }

    private int completeUtf8PrefixLength(byte @NotNull [] bytes) {
        if (bytes.length == 0) {
            return 0;
        }
        int leadIndex = bytes.length - 1;
        while (leadIndex >= 0 && (bytes[leadIndex] & 0xC0) == 0x80) {
            leadIndex--;
        }
        if (leadIndex < 0) {
            return 0;
        }
        int lead = bytes[leadIndex] & 0xFF;
        int expectedLength = 1;
        if ((lead & 0xE0) == 0xC0) {
            expectedLength = 2;
        } else if ((lead & 0xF0) == 0xE0) {
            expectedLength = 3;
        } else if ((lead & 0xF8) == 0xF0) {
            expectedLength = 4;
        }
        int actualLength = bytes.length - leadIndex;
        if (actualLength < expectedLength) {
            return leadIndex;
        }
        return bytes.length;
    }


    private @NotNull Map<String, Object> handleDevices(@NotNull RequestContext request) throws Exception {
        List<FridaDevice> devices = listAvailableDevices();

        List<Map<String, Object>> list = new ArrayList<>();
        for (FridaDevice device : devices) {
            Map<String, Object> item = deviceToMap(device);
            if (item != null) {
                list.add(item);
            }
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("count", list.size());
        data.put("devices", list);
        return data;
    }

    private @NotNull List<FridaDevice> listAvailableDevices() throws Exception {
        List<FridaDevice> devices = new ArrayList<>(fridaCliService.listDevices(project));
        for (String host : settingsService.getRemoteHosts()) {
            addHostDeviceIfMissing(devices, host, "remote");
        }

        ZaFridaProjectConfig config = loadProjectConfigBlocking(projectManager.getActiveProject());
        if (config != null
                && (config.connectionMode == FridaConnectionMode.REMOTE
                || config.connectionMode == FridaConnectionMode.GADGET)) {
            String host = String.format(
                    "%s:%s",
                    ZaFridaNetUtil.defaultHost(config.remoteHost),
                    ZaFridaNetUtil.defaultPort(config.remotePort)
            );
            String type = "remote";
            if (config.connectionMode == FridaConnectionMode.GADGET) {
                type = "gadget";
            }
            addHostDeviceIfMissing(devices, host, type);
        }
        return devices;
    }

    private void addHostDeviceIfMissing(@NotNull List<FridaDevice> devices,
                                        @Nullable String rawHost,
                                        @NotNull String type) {
        if (ZaStrUtil.isBlank(rawHost)) {
            return;
        }
        String host = rawHost.trim();
        for (FridaDevice device : devices) {
            if (host.equals(device.getHost())) {
                return;
            }
        }
        String name = "Remote";
        if ("gadget".equals(type)) {
            name = "Gadget";
        }
        devices.add(new FridaDevice(
                String.format("%s:%s", type, host),
                type,
                name,
                FridaDeviceMode.HOST,
                host
        ));
    }

    private @Nullable FridaDevice findRequestedDevice(@NotNull List<FridaDevice> devices,
                                                       @Nullable String id,
                                                       @Nullable String host) {
        for (FridaDevice device : devices) {
            if (ZaStrUtil.isNotBlank(id) && id.trim().equals(device.getId())) {
                return device;
            }
            if (ZaStrUtil.isNotBlank(host) && host.trim().equals(device.getHost())) {
                return device;
            }
        }
        return null;
    }


    private @NotNull Map<String, Object> handleProcesses(@NotNull RequestContext request) throws Exception {
        FridaDevice device = callOnUiThreadAndWait(() -> {
            ZaFridaRunPanel panel = runPanelRef.get();
            if (panel == null) {
                return null;
            }
            return panel.getSelectedDeviceForApi();
        });

        if (device == null) {
            throw new ApiException(409, "未选中设备，请先通过 /device/select 选择设备");
        }

        String scopeParam = request.get("scope");
        FridaProcessScope scope = parseProcessScope(scopeParam);

        List<FridaProcess> processes = fridaCliService.listProcesses(project, device, scope);

        List<Map<String, Object>> list = new ArrayList<>();
        for (FridaProcess proc : processes) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("pid", proc.getPid());
            item.put("name", proc.getName());
            item.put("identifier", proc.getIdentifier());
            list.add(item);
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("device", deviceToMap(device));
        data.put("scope", scope.name().toLowerCase(Locale.ROOT));
        data.put("count", list.size());
        data.put("processes", list);
        return data;
    }

    private static @NotNull FridaProcessScope parseProcessScope(@Nullable String raw) {
        if (ZaStrUtil.isBlank(raw)) {
            return FridaProcessScope.RUNNING_PROCESSES;
        }
        String normalized = raw.trim().toLowerCase(Locale.ROOT);
        if ("apps".equals(normalized) || "running_apps".equals(normalized)) {
            return FridaProcessScope.RUNNING_APPS;
        }
        if ("installed".equals(normalized) || "installed_apps".equals(normalized)) {
            return FridaProcessScope.INSTALLED_APPS;
        }
        return FridaProcessScope.RUNNING_PROCESSES;
    }


    private @NotNull Map<String, Object> handleAdbForceStop(@NotNull RequestContext request) throws Exception {
        String target = resolveAdbTarget(request);
        String deviceId = resolveCurrentDeviceId();

        CompletableFuture<Map<String, Object>> future = new CompletableFuture<>();
        List<String> logs = new ArrayList<>();

        adbService.forceStop(
                target,
                deviceId,
                logs::add,
                logs::add
        );

        return buildAdbResult("force-stop", target, logs);
    }

    private @NotNull Map<String, Object> handleAdbOpenApp(@NotNull RequestContext request) throws Exception {
        String target = resolveAdbTarget(request);
        String deviceId = resolveCurrentDeviceId();

        List<String> logs = new ArrayList<>();

        adbService.openApp(
                target,
                deviceId,
                logs::add,
                logs::add
        );

        return buildAdbResult("open-app", target, logs);
    }

    private @NotNull String resolveAdbTarget(@NotNull RequestContext request) throws Exception {
        String target = request.get("target");
        if (ZaStrUtil.isNotBlank(target)) {
            return target.trim();
        }
        String uiTarget = callOnUiThreadAndWait(() -> {
            ZaFridaRunPanel panel = runPanelRef.get();
            if (panel == null) {
                return "";
            }
            return panel.getTargetTextForApi();
        });
        if (ZaStrUtil.isBlank(uiTarget)) {
            throw new ApiException(400, "未指定 target 且当前 UI 中无目标应用");
        }
        return uiTarget.trim();
    }

    private @Nullable String resolveCurrentDeviceId() throws Exception {
        FridaDevice device = callOnUiThreadAndWait(() -> {
            ZaFridaRunPanel panel = runPanelRef.get();
            if (panel == null) {
                return null;
            }
            return panel.getSelectedDeviceForApi();
        });
        if (device == null) {
            return resolveSavedAdbDeviceId();
        }
        if (device.getMode() != FridaDeviceMode.DEVICE_ID) {
            return resolveSavedAdbDeviceId();
        }
        String id = device.getId();
        if (ZaStrUtil.isBlank(id) || "usb".equalsIgnoreCase(id)) {
            return null;
        }
        return id;
    }

    private @Nullable String resolveSavedAdbDeviceId() throws Exception {
        ZaFridaFridaProject activeProject = projectManager.getActiveProject();
        ZaFridaProjectConfig config = loadProjectConfigBlocking(activeProject);
        if (config == null || ZaStrUtil.isBlank(config.lastDeviceId)) {
            return null;
        }
        String deviceId = config.lastDeviceId.trim();
        if ("usb".equalsIgnoreCase(deviceId)) {
            return null;
        }
        return deviceId;
    }

    private @NotNull Map<String, Object> buildAdbResult(@NotNull String action,
                                                         @NotNull String target,
                                                         @NotNull List<String> logs) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("action", action);
        data.put("target", target);
        data.put("accepted", true);
        data.put("logs", logs);
        return data;
    }


    private @NotNull Map<String, Object> handleConsoleClear(@NotNull RequestContext request) throws Exception {
        String typeParam = request.get("type");
        String normalizedType = "";
        if (typeParam != null) {
            normalizedType = typeParam.trim();
        }
        boolean isRun = !"attach".equalsIgnoreCase(normalizedType);

        runOnUiThreadAndWait(() -> {
            ZaFridaRunPanel panel = runPanelRef.get();
            if (panel == null) {
                throw new ApiException(409, "RunPanel 尚未就绪");
            }
            ZaFridaConsolePanel console;
            if (isRun) {
                console = panel.getRunConsolePanelForApi();
            } else {
                console = panel.getAttachConsolePanelForApi();
            }
            console.clear();
        });

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("action", "console-clear");
        String sessionType = "attach";
        if (isRun) {
            sessionType = "run";
        }
        data.put("type", sessionType);
        data.put("accepted", true);
        return data;
    }


    private @NotNull Map<String, Object> handleDiagnostics(@NotNull RequestContext request) throws Exception {
        FridaDevice device = callOnUiThreadAndWait(() -> {
            ZaFridaRunPanel panel = runPanelRef.get();
            if (panel == null) {
                return null;
            }
            return panel.getSelectedDeviceForApi();
        });

        List<ZaFridaDiagnosticItem> items = diagnosticsService.createDefaultItems();
        CompletableFuture<List<ZaFridaDiagnosticItem>> future = new CompletableFuture<>();

        diagnosticsService.runDiagnostics(project, device, items, new ZaFridaDiagnosticsListener() {
            @Override
            public void onItemUpdated(@NotNull ZaFridaDiagnosticItem item) {
            }

            @Override
            public void onAllCompleted(@NotNull List<ZaFridaDiagnosticItem> completedItems) {
                future.complete(completedItems);
            }
        });

        List<ZaFridaDiagnosticItem> results;
        try {
            results = future.get(DIAGNOSTICS_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
            throw new ApiException(504, "诊断超时");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ApiException(500, "诊断被中断");
        } catch (ExecutionException e) {
            throw new ApiException(500, String.format("诊断执行失败: %s", e.getMessage()));
        }

        List<Map<String, Object>> itemList = new ArrayList<>();
        int successCount = 0;
        int failedCount = 0;
        for (ZaFridaDiagnosticItem item : results) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("id", item.getId());
            entry.put("title", item.getTitle());
            entry.put("status", item.getStatus().name().toLowerCase(Locale.ROOT));
            entry.put("message", item.getMessage());
            entry.put("tip", item.getTip());
            itemList.add(entry);

            if (item.getStatus() == ZaFridaDiagnosticStatus.SUCCESS) {
                successCount++;
            } else if (item.getStatus() == ZaFridaDiagnosticStatus.FAILED) {
                failedCount++;
            }
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("total", results.size());
        data.put("success", successCount);
        data.put("failed", failedCount);
        data.put("items", itemList);
        return data;
    }

    private @NotNull Map<String, Object> buildStateSummary() throws Exception {
        ZaFridaFridaProject active = projectManager.getActiveProject();
        ZaFridaProjectConfig cfg = loadProjectConfigBlocking(active);
        UiSnapshot uiSnapshot = captureUiSnapshot();

        Map<String, Object> api = new LinkedHashMap<>();
        api.put("host", BIND_HOST);
        api.put("port", boundPort);
        api.put("basePath", API_BASE);
        api.put("healthPath", API_HEALTH);

        Map<String, Object> session = new LinkedHashMap<>();
        session.put("runRunning", sessionService.isRunning(ZaFridaSessionType.RUN));
        session.put("attachRunning", sessionService.isRunning(ZaFridaSessionType.ATTACH));

        long runFileSize = computeFileSize(uiSnapshot.runLogPath);
        long attachFileSize = computeFileSize(uiSnapshot.attachLogPath);

        Map<String, Object> logs = new LinkedHashMap<>();
        logs.put("runPath", uiSnapshot.runLogPath);
        logs.put("attachPath", uiSnapshot.attachLogPath);
        logs.put("runFileSize", runFileSize);
        logs.put("attachFileSize", attachFileSize);
        logs.put("runSizeHuman", formatFileSize(runFileSize));
        logs.put("attachSizeHuman", formatFileSize(attachFileSize));

        Map<String, Object> ui = new LinkedHashMap<>();
        ui.put("target", uiSnapshot.target);
        ui.put("extraArgs", uiSnapshot.extraArgs);
        ui.put("runScript", uiSnapshot.runScript);
        ui.put("attachScript", uiSnapshot.attachScript);
        ui.put("selectedDevice", deviceToMap(uiSnapshot.selectedDevice));

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("api", api);
        data.put("activeProject", projectToMap(active));
        data.put("projects", projectListToMap(projectManager.listProjects()));
        data.put("config", configToMap(cfg));
        data.put("ui", ui);
        data.put("session", session);
        data.put("logs", logs);
        return data;
    }

    private @NotNull UiSnapshot captureUiSnapshot() throws Exception {
        ZaFridaRunPanel panel = runPanelRef.get();
        if (panel == null) {
            return UiSnapshot.empty();
        }
        return callOnUiThreadAndWait(() -> {
            ZaFridaRunPanel current = runPanelRef.get();
            if (current == null) {
                return UiSnapshot.empty();
            }
            FridaDevice selected = current.getSelectedDeviceForApi();
            String target = current.getTargetTextForApi();
            String extra = current.getExtraArgsForApi();
            String runScript = current.getRunScriptPathForApi();
            String attachScript = current.getAttachScriptPathForApi();

            ZaFridaConsolePanel runConsole = current.getRunConsolePanelForApi();
            ZaFridaConsolePanel attachConsole = current.getAttachConsolePanelForApi();

            String runPath = runConsole.getLogFilePath();
            String attachPath = attachConsole.getLogFilePath();
            return new UiSnapshot(target, extra, runScript, attachScript, selected, runPath, attachPath);
        });
    }

    private @Nullable ZaFridaProjectConfig loadProjectConfigBlocking(@Nullable ZaFridaFridaProject projectRef) throws Exception {
        if (projectRef == null) {
            return null;
        }
        CompletableFuture<ZaFridaProjectConfig> future = new CompletableFuture<>();
        projectManager.loadProjectConfigAsync(projectRef, future::complete);
        return waitFuture(future, "Load project config timeout");
    }

    private @Nullable ZaFridaFridaProject findProjectByName(@NotNull String name) {
        List<ZaFridaFridaProject> projects = projectManager.listProjects();
        for (ZaFridaFridaProject projectItem : projects) {
            if (name.equals(projectItem.getName())) {
                return projectItem;
            }
        }
        return null;
    }

    private @NotNull ZaFridaFridaProject requireActiveProject() {
        ZaFridaFridaProject active = projectManager.getActiveProject();
        if (active == null) {
            throw new ApiException(409, "No active project");
        }
        return active;
    }

    private @NotNull ZaFridaRunPanel requireRunPanel() {
        ZaFridaRunPanel panel = runPanelRef.get();
        if (panel == null) {
            throw new ApiException(409, "ZAFrida ToolWindow is not ready");
        }
        return panel;
    }

    private @NotNull VirtualFile resolveFridaScriptFile(@NotNull String rawPath,
                                                        @NotNull String sessionName) {
        String path = rawPath.trim();
        if (path.isEmpty()) {
            throw new ApiException(400, String.format("Invalid %s script: path is empty", sessionName));
        }
        VirtualFile file = LocalFileSystem.getInstance().refreshAndFindFileByPath(path);
        if (file == null || !file.isValid() || !ProjectFileUtil.isFridaScriptFile(file)) {
            throw new ApiException(400, String.format(
                    "Invalid %s script (expected an existing .js or .ts file): %s",
                    sessionName,
                    rawPath
            ));
        }
        return file;
    }

    private @NotNull ZaFridaPlatform parsePlatform(@NotNull String raw) {
        String normalized = raw.trim().toLowerCase(Locale.ROOT);
        if ("android".equals(normalized)) {
            return ZaFridaPlatform.ANDROID;
        }
        if ("ios".equals(normalized)) {
            return ZaFridaPlatform.IOS;
        }
        throw new ApiException(400, String.format("Unsupported platform: %s", raw));
    }

    private @NotNull FridaConnectionMode parseConnectionMode(@NotNull String raw) {
        String normalized = raw.trim().toLowerCase(Locale.ROOT);
        if ("usb".equals(normalized)) {
            return FridaConnectionMode.USB;
        }
        if ("remote".equals(normalized)) {
            return FridaConnectionMode.REMOTE;
        }
        if ("gadget".equals(normalized)) {
            return FridaConnectionMode.GADGET;
        }
        throw new ApiException(400, String.format("Unsupported connection mode: %s", raw));
    }

    private @NotNull ApiException mapFridaFailure(@NotNull FridaCliException error) {
        String message = safeErrorMessage(error);
        if (error.isTimedOut()) {
            return new ApiException(504, "FRIDA_COMMAND_TIMEOUT", true, message);
        }

        String details = String.format("%s\n%s\n%s", message, error.getStdout(), error.getStderr())
                .toLowerCase(Locale.ROOT);
        if (details.contains("unable to connect")
                || details.contains("device not found")
                || details.contains("device disconnected")
                || details.contains("transport is closed")
                || details.contains("connection closed")
                || details.contains("server is not running")
                || details.contains("timed out")) {
            return new ApiException(503, "FRIDA_DEVICE_UNAVAILABLE", true, message);
        }
        return new ApiException(500, "FRIDA_COMMAND_FAILED", false, message);
    }

    private static @NotNull String safeErrorMessage(@NotNull Throwable error) {
        String message = error.getMessage();
        if (ZaStrUtil.isBlank(message)) {
            message = error.getClass().getSimpleName();
        }
        if (message.length() > 4_000) {
            return message.substring(0, 4_000);
        }
        return message;
    }

    private @Nullable Integer parseOptionalPort(@Nullable String text) {
        if (ZaStrUtil.isBlank(text)) {
            return null;
        }
        int value = parseNonNegativeInt(text, -1, "port");
        if (value <= 0 || value > 65535) {
            throw new ApiException(400, String.format("Invalid port: %s", text));
        }
        return value;
    }

    private int parseNonNegativeInt(@Nullable String text, int defaultValue, @NotNull String fieldName) {
        if (ZaStrUtil.isBlank(text)) {
            return defaultValue;
        }
        String normalized = text.trim();
        try {
            int value = Integer.parseInt(normalized);
            if (value < 0) {
                throw new ApiException(400, String.format("Invalid %s: %s", fieldName, text));
            }
            return value;
        } catch (NumberFormatException e) {
            throw new ApiException(400, String.format("Invalid %s: %s", fieldName, text));
        }
    }

    private long parseNonNegativeLong(@Nullable String text, long defaultValue, @NotNull String fieldName) {
        if (ZaStrUtil.isBlank(text)) {
            return defaultValue;
        }
        try {
            long value = Long.parseLong(text.trim());
            if (value < 0L) {
                throw new ApiException(400, String.format("Invalid %s: %s", fieldName, text));
            }
            return value;
        } catch (NumberFormatException e) {
            throw new ApiException(400, String.format("Invalid %s: %s", fieldName, text));
        }
    }

    private @NotNull Path resolveReadableLogFile(@NotNull String rawPath) throws IOException {
        Path requested;
        try {
            requested = Paths.get(rawPath.trim()).toAbsolutePath().normalize();
        } catch (RuntimeException e) {
            throw new ApiException(400, String.format("Invalid log path: %s", rawPath));
        }
        if (!Files.isRegularFile(requested)) {
            throw new ApiException(404, String.format("Log file not found: %s", rawPath));
        }

        Path realFile = requested.toRealPath();
        for (Path root : resolveAllowedLogRoots()) {
            if (!Files.isDirectory(root)) {
                continue;
            }
            Path realRoot = root.toRealPath();
            if (realFile.startsWith(realRoot)) {
                return realFile;
            }
        }
        throw new ApiException(
                403,
                "LOG_PATH_OUTSIDE_PROJECT",
                false,
                "Only ZAFrida log files under the current IDE project may be read"
        );
    }

    private @NotNull List<Path> resolveAllowedLogRoots() {
        Set<Path> roots = new LinkedHashSet<>();
        String basePath = project.getBasePath();
        if (ZaStrUtil.isBlank(basePath)) {
            return new ArrayList<>();
        }

        Path ideRoot;
        try {
            ideRoot = Paths.get(basePath).toAbsolutePath().normalize();
        } catch (RuntimeException e) {
            LOG.debug(String.format("[ZAFrida API] Invalid IDE project path: %s", basePath), e);
            return new ArrayList<>();
        }
        addLogRoot(roots, ideRoot);

        for (ZaFridaFridaProject fridaProject : projectManager.listProjects()) {
            try {
                Path projectRoot = ideRoot.resolve(fridaProject.getRelativeDir()).normalize();
                if (projectRoot.startsWith(ideRoot)) {
                    addLogRoot(roots, projectRoot);
                }
            } catch (RuntimeException e) {
                LOG.debug(String.format("[ZAFrida API] Invalid ZAFrida project path: %s",
                        fridaProject.getRelativeDir()), e);
            }
        }
        return new ArrayList<>(roots);
    }

    private void addLogRoot(@NotNull Set<Path> roots, @NotNull Path base) {
        Path logRoot = ZaFridaLogPaths.resolveLogsDir(base.toString());
        if (logRoot != null) {
            roots.add(logRoot.toAbsolutePath().normalize());
        }
    }

    private boolean matchesLogType(@NotNull Path path, @NotNull String type) {
        if ("all".equals(type)) {
            return true;
        }
        return type.equals(detectLogType(path));
    }

    private @NotNull String detectLogType(@NotNull Path path) {
        String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
        if (name.endsWith("_attach.log") || name.matches(".*_attach_[0-9]+\\.log")) {
            return "attach";
        }
        if (name.endsWith("_run.log") || name.matches(".*_run_[0-9]+\\.log")) {
            return "run";
        }
        return "other";
    }

    private long lastModifiedMillis(@NotNull Path path) {
        try {
            return Files.getLastModifiedTime(path).toMillis();
        } catch (IOException e) {
            LOG.debug(String.format("[ZAFrida API] Read log mtime failed: %s", path), e);
            return 0L;
        }
    }

    private static @NotNull String formatFileSize(long bytes) {
        if (bytes < 1024L) {
            return bytes + " B";
        }
        if (bytes < 1024L * 1024L) {
            return String.format("%.1f KB", bytes / 1024.0);
        }
        if (bytes < 1024L * 1024L * 1024L) {
            return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        }
        return String.format("%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }

    private long computeFileSize(@Nullable String path) {
        return computeFileSize(path, true);
    }

    private long computeFileSize(@Nullable String path, boolean existsHint) {
        if (ZaStrUtil.isBlank(path)) {
            return 0L;
        }
        String trimmed = path.trim();
        if (trimmed.startsWith("(")) {
            return 0L;
        }
        if (!existsHint) {
            return 0L;
        }
        try {
            Path filePath = Paths.get(trimmed);
            if (Files.exists(filePath) && Files.isRegularFile(filePath)) {
                return Files.size(filePath);
            }
        } catch (Exception e) {
            LOG.debug(String.format("[ZAFrida API] 获取文件大小失败: %s", trimmed), e);
        }
        return 0L;
    }

    private @NotNull Map<String, Object> actionResult(@NotNull String action) {
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("action", action);
        data.put("accepted", true);
        return data;
    }

    private @NotNull Map<String, Object> buildSessionStatus(@NotNull ZaFridaSessionType type,
                                                            @Nullable String logPath) {
        RunningSession runningSession = sessionService.getRunningSession(type);
        boolean running = runningSession != null;
        String effectiveLogPath = logPath;
        if (runningSession != null) {
            effectiveLogPath = runningSession.getLogFilePath();
        }
        Map<String, Object> data = new LinkedHashMap<>();
        String state = "stopped";
        if (running) {
            state = "running";
        }
        data.put("state", state);
        data.put("running", running);
        data.put("logPath", effectiveLogPath);
        data.put("logFileSize", computeFileSize(effectiveLogPath));
        if (runningSession != null) {
            data.put("startedAt", runningSession.getStartedAtEpochMillis());
            data.put("command", runningSession.getCommandLine());
        }
        return data;
    }

    private @Nullable Map<String, Object> environmentToMap(@Nullable PythonEnvInfo environment) {
        if (environment == null) {
            return null;
        }
        ZaFridaSettingsState settings = settingsService.getState();
        Map<String, Object> tools = new LinkedHashMap<>();
        tools.put("frida", ProjectPythonEnvResolver.findTool(environment, settings.fridaExecutable));
        tools.put("fridaPs", ProjectPythonEnvResolver.findTool(environment, settings.fridaPsExecutable));
        tools.put("fridaLsDevices", ProjectPythonEnvResolver.findTool(environment, settings.fridaLsDevicesExecutable));

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("source", environment.getSource().name().toLowerCase(Locale.ROOT));
        data.put("python", environment.getPythonHome());
        data.put("root", environment.getEnvRoot());
        data.put("pathEntries", environment.getPathEntries());
        data.put("tools", tools);
        return data;
    }

    private @Nullable Map<String, Object> projectToMap(@Nullable ZaFridaFridaProject projectItem) {
        if (projectItem == null) {
            return null;
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("name", projectItem.getName());
        data.put("platform", projectItem.getPlatform().name().toLowerCase(Locale.ROOT));
        data.put("relativeDir", projectItem.getRelativeDir());
        return data;
    }

    private @NotNull List<Map<String, Object>> projectListToMap(@NotNull List<ZaFridaFridaProject> projects) {
        List<Map<String, Object>> list = new ArrayList<>();
        for (ZaFridaFridaProject projectItem : projects) {
            Map<String, Object> map = projectToMap(projectItem);
            if (map != null) {
                list.add(map);
            }
        }
        return list;
    }

    private @Nullable Map<String, Object> configToMap(@Nullable ZaFridaProjectConfig cfg) {
        if (cfg == null) {
            return null;
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("connectionMode", cfg.connectionMode.name().toLowerCase(Locale.ROOT));
        data.put("remoteHost", cfg.remoteHost);
        data.put("remotePort", cfg.remotePort);
        data.put("lastTarget", cfg.lastTarget);
        data.put("extraArgs", cfg.extraArgs);
        data.put("mainScript", cfg.mainScript);
        data.put("attachScript", cfg.attachScript);
        data.put("lastDeviceId", cfg.lastDeviceId);
        data.put("lastDeviceHost", cfg.lastDeviceHost);
        data.put("pythonEnvironmentPath", cfg.pythonEnvironmentPath);
        return data;
    }

    private @Nullable Map<String, Object> deviceToMap(@Nullable FridaDevice device) {
        if (device == null) {
            return null;
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("id", device.getId());
        data.put("name", device.getName());
        data.put("type", device.getType());
        data.put("host", device.getHost());
        data.put("mode", device.getMode().name().toLowerCase(Locale.ROOT));
        return data;
    }

    private <T> @NotNull T callOnUiThreadAndWait(@NotNull Callable<T> callable) throws Exception {
        if (ApplicationManager.getApplication().isDispatchThread()) {
            return callable.call();
        }

        CompletableFuture<T> future = new CompletableFuture<>();
        ApplicationManager.getApplication().invokeAndWait(() -> {
            if (project.isDisposed()) {
                future.completeExceptionally(new ApiException(410, "Project disposed"));
                return;
            }
            try {
                T value = callable.call();
                future.complete(value);
            } catch (Throwable t) {
                future.completeExceptionally(t);
            }
        }, ModalityState.any());
        return waitFuture(future, "UI operation timeout");
    }

    private void runOnUiThreadAndWait(@NotNull Runnable action) throws Exception {
        callOnUiThreadAndWait(() -> {
            action.run();
            return Boolean.TRUE;
        });
    }

    private void awaitVoidFuture(@NotNull CompletableFuture<Void> future, @NotNull String timeoutMessage) {
        try {
            future.get(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ApiException(500, "Interrupted");
        } catch (TimeoutException e) {
            throw new ApiException(504, timeoutMessage);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof ApiException apiException) {
                throw apiException;
            }
            String message = null;
            if (cause != null) {
                message = cause.getMessage();
            }
            if (ZaStrUtil.isBlank(message)) {
                message = "Execution failed";
            }
            throw new ApiException(500, message);
        }
    }

    private <T> @NotNull T waitFuture(@NotNull CompletableFuture<T> future, @NotNull String timeoutMessage) {
        try {
            return future.get(DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ApiException(500, "Interrupted");
        } catch (TimeoutException e) {
            throw new ApiException(504, timeoutMessage);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof ApiException apiException) {
                throw apiException;
            }
            String message = null;
            if (cause != null) {
                message = cause.getMessage();
            }
            if (ZaStrUtil.isBlank(message)) {
                message = "Execution failed";
            }
            throw new ApiException(500, message);
        }
    }

    private void writeNoContent(@NotNull HttpExchange exchange) throws IOException {
        fillCommonHeaders(exchange);
        exchange.sendResponseHeaders(204, -1);
    }

    private void writeSuccess(@NotNull HttpExchange exchange, @NotNull Map<String, Object> data) throws IOException {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("ok", true);
        payload.put("status", 200);
        payload.put("data", data);
        writeJson(exchange, 200, payload);
    }

    private void writeError(@NotNull HttpExchange exchange,
                            int statusCode,
                            @NotNull String errorCode,
                            boolean retryable,
                            @NotNull String message) throws IOException {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("ok", false);
        payload.put("status", statusCode);
        payload.put("errorCode", errorCode);
        payload.put("retryable", retryable);
        payload.put("message", message);
        writeJson(exchange, statusCode, payload);
    }

    private void writeJson(@NotNull HttpExchange exchange,
                           int statusCode,
                           @NotNull Map<String, Object> payload) throws IOException {
        byte[] bytes = toJson(payload).getBytes(StandardCharsets.UTF_8);
        Headers headers = exchange.getResponseHeaders();
        fillCommonHeaders(exchange);
        headers.set("Content-Type", "application/json; charset=utf-8");
        headers.set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(statusCode, bytes.length);
        exchange.getResponseBody().write(bytes);
    }

    private void fillCommonHeaders(@NotNull HttpExchange exchange) {
        Headers headers = exchange.getResponseHeaders();
        String origin = exchange.getRequestHeaders().getFirst("Origin");
        if (ZaStrUtil.isNotBlank(origin) && isAllowedLocalOrigin(origin)) {
            headers.set("Access-Control-Allow-Origin", origin);
            headers.set("Vary", "Origin");
        }
        headers.set("Access-Control-Allow-Headers", "Content-Type");
        headers.set("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
        headers.set("Cache-Control", "no-store");
    }

    private void validateRequestOrigin(@NotNull HttpExchange exchange) {
        String origin = exchange.getRequestHeaders().getFirst("Origin");
        if (ZaStrUtil.isBlank(origin)) {
            return;
        }
        if (!isAllowedLocalOrigin(origin)) {
            throw new ApiException(403, "ORIGIN_NOT_ALLOWED", false,
                    String.format("Browser origin is not allowed: %s", origin));
        }
    }

    private boolean isAllowedLocalOrigin(@NotNull String origin) {
        try {
            URI uri = URI.create(origin.trim());
            String host = uri.getHost();
            if (host == null) {
                return false;
            }
            return "127.0.0.1".equals(host)
                    || "localhost".equalsIgnoreCase(host)
                    || "::1".equals(host)
                    || "[::1]".equals(host);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private @NotNull String toJson(@Nullable Object value) {
        if (value == null) {
            return "null";
        }
        if (value instanceof String text) {
            return "\"" + escapeJson(text) + "\"";
        }
        if (value instanceof Number || value instanceof Boolean) {
            return String.valueOf(value);
        }
        if (value instanceof Map<?, ?> map) {
            StringBuilder builder = new StringBuilder();
            builder.append("{");
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    builder.append(",");
                }
                first = false;
                builder.append("\"");
                builder.append(escapeJson(String.valueOf(entry.getKey())));
                builder.append("\":");
                builder.append(toJson(entry.getValue()));
            }
            builder.append("}");
            return builder.toString();
        }
        if (value instanceof Iterable<?> iterable) {
            StringBuilder builder = new StringBuilder();
            builder.append("[");
            boolean first = true;
            for (Object item : iterable) {
                if (!first) {
                    builder.append(",");
                }
                first = false;
                builder.append(toJson(item));
            }
            builder.append("]");
            return builder.toString();
        }
        if (value.getClass().isArray()) {
            Object[] array = (Object[]) value;
            List<Object> list = new ArrayList<>();
            for (Object item : array) {
                list.add(item);
            }
            return toJson(list);
        }
        return "\"" + escapeJson(String.valueOf(value)) + "\"";
    }

    private @NotNull String escapeJson(@NotNull String text) {
        StringBuilder builder = new StringBuilder();
        int length = text.length();
        for (int i = 0; i < length; i++) {
            char ch = text.charAt(i);
            switch (ch) {
                case '\\' -> builder.append("\\\\");
                case '"' -> builder.append("\\\"");
                case '\n' -> builder.append("\\n");
                case '\r' -> builder.append("\\r");
                case '\t' -> builder.append("\\t");
                default -> {
                    if (ch < 0x20) {
                        builder.append(String.format("\\u%04x", (int) ch));
                    } else {
                        builder.append(ch);
                    }
                }
            }
        }
        return builder.toString();
    }

    @Override
    public void dispose() {
        stopServerSafely();
    }

    private interface ApiHandler {
        @NotNull Map<String, Object> handle(@NotNull RequestContext request) throws Exception;
    }

    private static final class ApiException extends RuntimeException {
        private final int statusCode;
        private final @NotNull String errorCode;
        private final boolean retryable;

        private ApiException(int statusCode, @NotNull String message) {
            this(statusCode, String.format("HTTP_%s", statusCode), statusCode >= 500, message);
        }

        private ApiException(int statusCode,
                             @NotNull String errorCode,
                             boolean retryable,
                             @NotNull String message) {
            super(message);
            this.statusCode = statusCode;
            this.errorCode = errorCode;
            this.retryable = retryable;
        }
    }

    private static final class RequestContext {
        private final @NotNull Map<String, String> params;

        private RequestContext(@NotNull Map<String, String> params) {
            this.params = params;
        }

        private static @NotNull RequestContext from(@NotNull HttpExchange exchange) throws IOException {
            Map<String, String> params = new LinkedHashMap<>();
            URI uri = exchange.getRequestURI();
            if (uri != null) {
                parseParamString(uri.getRawQuery(), params);
            }

            String method = exchange.getRequestMethod();
            if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method)) {
                String contentLength = exchange.getRequestHeaders().getFirst("Content-Length");
                if (ZaStrUtil.isNotBlank(contentLength)) {
                    try {
                        long declaredLength = Long.parseLong(contentLength.trim());
                        if (declaredLength > MAX_REQUEST_BODY_BYTES) {
                            throw new ApiException(413, "REQUEST_BODY_TOO_LARGE", false,
                                    String.format("Request body exceeds %s bytes", MAX_REQUEST_BODY_BYTES));
                        }
                    } catch (NumberFormatException e) {
                        throw new ApiException(400, "INVALID_CONTENT_LENGTH", false,
                                String.format("Invalid Content-Length: %s", contentLength));
                    }
                }
                byte[] bodyBytes = readAll(exchange.getRequestBody());
                if (bodyBytes.length > 0) {
                    String body = new String(bodyBytes, StandardCharsets.UTF_8);
                    parseParamString(body, params);
                }
            }

            return new RequestContext(params);
        }

        private static void parseParamString(@Nullable String raw, @NotNull Map<String, String> out) {
            if (ZaStrUtil.isBlank(raw)) {
                return;
            }
            String[] pairs = raw.split("&");
            for (String pair : pairs) {
                if (pair.isEmpty()) {
                    continue;
                }
                String key;
                String value;
                int index = pair.indexOf('=');
                if (index < 0) {
                    key = decode(pair);
                    value = "";
                } else {
                    key = decode(pair.substring(0, index));
                    value = decode(pair.substring(index + 1));
                }
                if (ZaStrUtil.isBlank(key)) {
                    continue;
                }
                out.put(key, value);
            }
        }

        private static byte @NotNull [] readAll(@NotNull InputStream inputStream) throws IOException {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = inputStream.read(buffer)) >= 0) {
                if (read == 0) {
                    continue;
                }
                if (outputStream.size() + read > MAX_REQUEST_BODY_BYTES) {
                    throw new ApiException(413, "REQUEST_BODY_TOO_LARGE", false,
                            String.format("Request body exceeds %s bytes", MAX_REQUEST_BODY_BYTES));
                }
                outputStream.write(buffer, 0, read);
            }
            return outputStream.toByteArray();
        }

        private static @NotNull String decode(@NotNull String text) {
            try {
                return URLDecoder.decode(text, StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                throw new ApiException(400, "INVALID_PARAMETER_ENCODING", false,
                        "Request parameter contains invalid percent encoding");
            }
        }

        private @Nullable String get(@NotNull String key) {
            return params.get(key);
        }

        private @NotNull String getOrDefault(@NotNull String key, @NotNull String defaultValue) {
            String value = params.get(key);
            if (value == null) {
                return defaultValue;
            }
            return value;
        }

        private @NotNull String require(@NotNull String key) {
            String value = params.get(key);
            if (ZaStrUtil.isBlank(value)) {
                throw new ApiException(400, String.format("Missing parameter: %s", key));
            }
            return Objects.requireNonNull(value);
        }
    }

    private static final class UiSnapshot {
        private final @NotNull String target;
        private final @NotNull String extraArgs;
        private final @NotNull String runScript;
        private final @NotNull String attachScript;
        private final @Nullable FridaDevice selectedDevice;
        private final @Nullable String runLogPath;
        private final @Nullable String attachLogPath;

        private UiSnapshot(@NotNull String target,
                           @NotNull String extraArgs,
                           @NotNull String runScript,
                           @NotNull String attachScript,
                           @Nullable FridaDevice selectedDevice,
                           @Nullable String runLogPath,
                           @Nullable String attachLogPath) {
            this.target = target;
            this.extraArgs = extraArgs;
            this.runScript = runScript;
            this.attachScript = attachScript;
            this.selectedDevice = selectedDevice;
            this.runLogPath = runLogPath;
            this.attachLogPath = attachLogPath;
        }

        private static @NotNull UiSnapshot empty() {
            return new UiSnapshot("", "", "", "", null, null, null);
        }
    }

    private static final class LogState {
        private final @NotNull String path;
        private final @NotNull String consoleText;
        private final boolean existsOnDisk;
        private final boolean consoleTruncated;

        private LogState(@NotNull String path,
                         @NotNull String consoleText,
                         boolean existsOnDisk,
                         boolean consoleTruncated) {
            this.path = path;
            this.consoleText = consoleText;
            this.existsOnDisk = existsOnDisk;
            this.consoleTruncated = consoleTruncated;
        }
    }

    private static final class ByteChunk {
        private final long startOffset;
        private final byte @NotNull [] bytes;

        private ByteChunk(long startOffset, byte @NotNull [] bytes) {
            this.startOffset = startOffset;
            this.bytes = bytes;
        }
    }
}
