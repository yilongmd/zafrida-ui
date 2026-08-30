package com.zafrida.ui.settings;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.options.SearchableConfigurable;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.project.ProjectManager;
import com.zafrida.ui.api.ZaFridaLocalHttpApiService;
import com.zafrida.ui.frida.FridaCliService;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JComponent;
import java.util.ArrayList;
import java.util.List;

public final class ZaFridaSettingsConfigurable implements SearchableConfigurable {

    private final ZaFridaSettingsService settingsService;
    private @Nullable ZaFridaSettingsComponent component;

    public ZaFridaSettingsConfigurable() {
        this.settingsService = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
    }

    @Override
    public @NotNull String getId() {
        return "com.zafrida.ui.settings";
    }

    @Override
    public String getDisplayName() {
        return "ZAFrida";
    }

    @Override
    public @Nullable JComponent createComponent() {
        ZaFridaSettingsComponent c = new ZaFridaSettingsComponent();
        c.reset(settingsService.getState());
        c.bindSkillsApiActions(this::handleManualStartSkillsApi, this::handleManualStopSkillsApi);
        this.component = c;
        refreshSkillsApiStatusAsync();
        return c.getPanel();
    }

    @Override
    public boolean isModified() {
        if (component == null) {
            return false;
        }

        ZaFridaSettingsState copy = createSnapshotFromCurrentState();
        component.applyTo(copy);

        ZaFridaSettingsState current = settingsService.getState();
        if (!safeEq(copy.fridaExecutable, current.fridaExecutable)) {
            return true;
        }
        if (!safeEq(copy.fridaPsExecutable, current.fridaPsExecutable)) {
            return true;
        }
        if (!safeEq(copy.fridaLsDevicesExecutable, current.fridaLsDevicesExecutable)) {
            return true;
        }
        if (!safeEq(copy.fridaVersion, current.fridaVersion)) {
            return true;
        }
        if (!safeEq(copy.vscodeExecutable, current.vscodeExecutable)) {
            return true;
        }
        if (!safeEq(copy.editor010Executable, current.editor010Executable)) {
            return true;
        }
        if (!safeEq(copy.logsDirName, current.logsDirName)) {
            return true;
        }
        if (!safeEq(copy.defaultRemoteHost, current.defaultRemoteHost)) {
            return true;
        }
        if (copy.defaultRemotePort != current.defaultRemotePort) {
            return true;
        }
        if (copy.useIdeScriptChooser != current.useIdeScriptChooser) {
            return true;
        }
        if (!safeEq(copy.templatesRootMode, current.templatesRootMode)) {
            return true;
        }
        if (copy.enableSkillsHttpApi != current.enableSkillsHttpApi) {
            return true;
        }
        if (copy.skillsApiPort != current.skillsApiPort) {
            return true;
        }

        if (copy.remoteHosts == null && current.remoteHosts != null && !current.remoteHosts.isEmpty()) {
            return true;
        }
        if (copy.remoteHosts != null && current.remoteHosts == null && !copy.remoteHosts.isEmpty()) {
            return true;
        }
        if (copy.remoteHosts != null && current.remoteHosts != null && !copy.remoteHosts.equals(current.remoteHosts)) {
            return true;
        }

        return false;
    }

    @Override
    public void apply() {
        if (component == null) {
            return;
        }
        ZaFridaSettingsState current = settingsService.getState();
        boolean oldEnabled = current.enableSkillsHttpApi;
        int oldPort = current.skillsApiPort;

        ZaFridaSettingsState newState = createSnapshotFromCurrentState();
        component.applyTo(newState);
        settingsService.loadState(newState);
        ApplicationManager.getApplication().getService(FridaCliService.class).clearDetectedProjectVersions();

        applySkillsApiChangeAsync(oldEnabled, oldPort, newState.enableSkillsHttpApi, newState.skillsApiPort);
    }

    @Override
    public void reset() {
        if (component != null) {
            component.reset(settingsService.getState());
            refreshSkillsApiStatusAsync();
        }
    }

    @Override
    public void disposeUIResources() {
        component = null;
    }

    private void handleManualStartSkillsApi() {
        ZaFridaSettingsComponent currentComponent = component;
        if (currentComponent == null) {
            return;
        }
        currentComponent.setSkillsApiStatus("Starting...", false);

        if (!currentComponent.isSkillsApiEnabled()) {
            currentComponent.setSkillsApiStatus("Disabled", false);
            return;
        }
        int requestedPort = currentComponent.getSkillsApiPort();

        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            ApiControlResult result = startSkillsApiForOpenProjects(false, requestedPort);
            ApplicationManager.getApplication().invokeLater(() -> {
                ZaFridaSettingsComponent c = component;
                if (c == null) {
                    return;
                }
                c.setSkillsApiStatus(result.statusText, result.running);
                if (!result.errorMessage.isEmpty()) {
                    c.showSkillsApiTip(result.errorMessage, true);
                }
            });
        });
    }

    private void handleManualStopSkillsApi() {
        ZaFridaSettingsComponent currentComponent = component;
        if (currentComponent == null) {
            return;
        }
        currentComponent.setSkillsApiStatus("Stopping...", true);
        boolean enabledInEditor = currentComponent.isSkillsApiEnabled();

        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            stopSkillsApiForOpenProjects();
            ApplicationManager.getApplication().invokeLater(() -> {
                ZaFridaSettingsComponent c = component;
                if (c == null) {
                    return;
                }
                if (enabledInEditor) {
                    c.setSkillsApiStatus("Stopped", false);
                } else {
                    c.setSkillsApiStatus("Disabled", false);
                }
            });
        });
    }

    private void applySkillsApiChangeAsync(boolean oldEnabled, int oldPort, boolean newEnabled, int newPort) {
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            if (!newEnabled) {
                stopSkillsApiForOpenProjects();
                ApplicationManager.getApplication().invokeLater(() -> {
                    ZaFridaSettingsComponent c = component;
                    if (c != null) {
                        c.setSkillsApiStatus("Disabled", false);
                    }
                });
                return;
            }

            boolean shouldRestart = !oldEnabled || oldPort != newPort;
            ApiControlResult result = startSkillsApiForOpenProjects(shouldRestart, null);
            ApplicationManager.getApplication().invokeLater(() -> {
                ZaFridaSettingsComponent c = component;
                if (c == null) {
                    return;
                }
                c.setSkillsApiStatus(result.statusText, result.running);
                if (!result.errorMessage.isEmpty()) {
                    c.showSkillsApiTip(result.errorMessage, true);
                }
            });
        });
    }

    private void refreshSkillsApiStatusAsync() {
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            ApiControlResult result = querySkillsApiStatus();
            ApplicationManager.getApplication().invokeLater(() -> {
                ZaFridaSettingsComponent c = component;
                if (c != null) {
                    c.setSkillsApiStatus(result.statusText, result.running);
                }
            });
        });
    }

    private @NotNull ApiControlResult querySkillsApiStatus() {
        List<Project> openProjects = listOpenProjects();
        if (openProjects.isEmpty()) {
            if (settingsService.getState().enableSkillsHttpApi) {
                return new ApiControlResult(false, "No open project", "");
            }
            return new ApiControlResult(false, "Disabled", "");
        }

        int runningCount = 0;
        int samplePort = -1;
        for (Project project : openProjects) {
            ZaFridaLocalHttpApiService service = project.getService(ZaFridaLocalHttpApiService.class);
            if (service.isServerRunning()) {
                runningCount++;
                if (samplePort <= 0) {
                    samplePort = service.getBoundPort();
                }
            }
        }

        if (runningCount <= 0) {
            if (settingsService.getState().enableSkillsHttpApi) {
                return new ApiControlResult(false, "Stopped", "");
            }
            return new ApiControlResult(false, "Disabled", "");
        }
        return new ApiControlResult(true, String.format("Running (%s, port=%s)", runningCount, samplePort), "");
    }

    private @NotNull ApiControlResult startSkillsApiForOpenProjects(boolean restart,
                                                                    @Nullable Integer requestedPort) {
        List<Project> openProjects = listOpenProjects();
        if (openProjects.isEmpty()) {
            return new ApiControlResult(false, "No open project", "");
        }

        int runningCount = 0;
        int samplePort = -1;
        List<String> errors = new ArrayList<>();
        for (Project project : openProjects) {
            ZaFridaLocalHttpApiService service = project.getService(ZaFridaLocalHttpApiService.class);
            boolean ok;
            boolean portChanged = requestedPort != null
                    && service.isServerRunning()
                    && service.getBoundPort() != requestedPort;
            if (restart || portChanged) {
                if (requestedPort == null) {
                    ok = service.restartServerNow();
                } else {
                    ok = service.restartServerNow(requestedPort);
                }
            } else {
                if (requestedPort == null) {
                    ok = service.startServerNow();
                } else {
                    ok = service.startServerNow(requestedPort);
                }
            }
            if (ok && service.isServerRunning()) {
                runningCount++;
                if (samplePort <= 0) {
                    samplePort = service.getBoundPort();
                }
                continue;
            }

            String error = service.getLastStartError();
            if (error == null || error.isEmpty()) {
                error = "Unknown start error";
            }
            errors.add(String.format("%s: %s", project.getName(), error));
        }

        if (runningCount <= 0) {
            String firstError;
            if (errors.isEmpty()) {
                firstError = "Skills HTTP API start failed";
            } else {
                firstError = errors.get(0);
            }
            return new ApiControlResult(false, "Start failed", firstError);
        }

        if (errors.isEmpty()) {
            return new ApiControlResult(true, String.format("Running (%s, port=%s)", runningCount, samplePort), "");
        }
        return new ApiControlResult(
                true,
                String.format("Running (%s, port=%s, partial)", runningCount, samplePort),
                errors.get(0)
        );
    }

    private void stopSkillsApiForOpenProjects() {
        List<Project> openProjects = listOpenProjects();
        for (Project project : openProjects) {
            ZaFridaLocalHttpApiService service = project.getService(ZaFridaLocalHttpApiService.class);
            service.stopServerNow();
        }
    }

    private @NotNull List<Project> listOpenProjects() {
        Project[] projects = ProjectManager.getInstance().getOpenProjects();
        List<Project> list = new ArrayList<>();
        for (Project project : projects) {
            if (project != null && !project.isDisposed()) {
                list.add(project);
            }
        }
        return list;
    }

    private @NotNull ZaFridaSettingsState createSnapshotFromCurrentState() {
        ZaFridaSettingsState current = settingsService.getState();
        ZaFridaSettingsState copy = new ZaFridaSettingsState();
        copy.fridaExecutable = current.fridaExecutable;
        copy.fridaPsExecutable = current.fridaPsExecutable;
        copy.fridaLsDevicesExecutable = current.fridaLsDevicesExecutable;
        copy.fridaVersion = current.fridaVersion;
        copy.vscodeExecutable = current.vscodeExecutable;
        copy.editor010Executable = current.editor010Executable;
        copy.logsDirName = current.logsDirName;
        copy.defaultRemoteHost = current.defaultRemoteHost;
        copy.defaultRemotePort = current.defaultRemotePort;
        copy.useIdeScriptChooser = current.useIdeScriptChooser;
        copy.templatesRootMode = current.templatesRootMode;
        copy.enableSkillsHttpApi = current.enableSkillsHttpApi;
        copy.skillsApiPort = current.skillsApiPort;
        copy.remoteHosts = settingsService.getRemoteHosts();
        return copy;
    }

    private static boolean safeEq(String a, String b) {
        if (a == null) {
            return b == null;
        }
        return a.equals(b);
    }

    private static final class ApiControlResult {
        private final boolean running;
        private final @NotNull String statusText;
        private final @NotNull String errorMessage;

        private ApiControlResult(boolean running, @NotNull String statusText, @NotNull String errorMessage) {
            this.running = running;
            this.statusText = statusText;
            this.errorMessage = errorMessage;
        }
    }
}
