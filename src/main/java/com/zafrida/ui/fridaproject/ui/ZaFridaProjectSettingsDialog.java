package com.zafrida.ui.fridaproject.ui;

import com.intellij.icons.AllIcons;
import com.intellij.openapi.fileChooser.FileChooser;
import com.intellij.openapi.fileChooser.FileChooserDescriptor;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.application.ModalityState;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.project.ProjectUtil;
import com.intellij.openapi.ui.ComboBox;
import com.intellij.openapi.ui.DialogWrapper;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.vfs.LocalFileSystem;
import com.intellij.openapi.vfs.VirtualFile;
import com.zafrida.ui.frida.FridaCliService;
import com.zafrida.ui.frida.FridaConnectionMode;
import com.zafrida.ui.frida.FridaDevice;
import com.zafrida.ui.frida.FridaDeviceMode;
import com.zafrida.ui.frida.FridaProcess;
import com.zafrida.ui.frida.FridaProcessScope;
import com.zafrida.ui.fridaproject.ZaFridaFridaProject;
import com.zafrida.ui.fridaproject.ZaFridaProjectConfig;
import com.zafrida.ui.fridaproject.ZaFridaProjectManager;
import com.zafrida.ui.python.ProjectPythonEnvResolver;
import com.zafrida.ui.python.PythonEnvInfo;
import com.zafrida.ui.python.PythonEnvResolutionException;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.settings.ZaFridaSettingsState;
import com.zafrida.ui.util.ZaFridaIcons;
import com.zafrida.ui.util.ZaFridaNetUtil;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.function.Consumer;
import java.util.function.Supplier;
import com.intellij.ui.components.JBTextField;

public final class ZaFridaProjectSettingsDialog extends DialogWrapper {

    private final Project project;
    private final ZaFridaProjectManager projectManager;
    private final FridaCliService fridaCliService;
    private final Supplier<FridaDevice> deviceSupplier;
    private final @Nullable Consumer<String> errorLogger;

    private final ButtonGroup targetGroup = new ButtonGroup();

    private final ComboBox<FridaConnectionMode> connectionModeCombo = new ComboBox<>(FridaConnectionMode.values());
    private final JBTextField remoteHostField = new JBTextField();
    private final JBTextField remotePortField = new JBTextField();

    private final JRadioButton manualTargetRadio = new JRadioButton("Manual");
    private final JRadioButton selectTargetRadio = new JRadioButton("Select from device");
    private final JBTextField manualTargetField = new JBTextField();

    private final ComboBox<FridaProcessScope> scopeCombo = new ComboBox<>(FridaProcessScope.values());
    private final ComboBox<String> targetCombo = new ComboBox<>();
    private final JButton refreshTargetsBtn = new JButton("Refresh");

    private final JLabel projectInfoLabel = new JLabel();

    private final ComboBox<String> pythonEnvironmentCombo = new ComboBox<>();
    private final JButton browsePythonEnvironmentBtn = new JButton("Browse...");
    private final JButton useProjectPythonBtn = new JButton("Default");
    private final JButton testPythonEnvironmentBtn = new JButton("Test");

    private @Nullable ZaFridaFridaProject activeProject;
    private @Nullable ZaFridaProjectConfig activeProjectConfig;
    private int pythonValidationGeneration;
    private int targetRefreshGeneration;

    public ZaFridaProjectSettingsDialog(@NotNull Project project,
                                        @NotNull ZaFridaProjectManager projectManager,
                                        @NotNull FridaCliService fridaCliService,
                                        @NotNull Supplier<FridaDevice> deviceSupplier,
                                        @Nullable Consumer<String> errorLogger) {
        super(project, true);
        this.project = project;
        this.projectManager = projectManager;
        this.fridaCliService = fridaCliService;
        this.deviceSupplier = deviceSupplier;
        this.errorLogger = errorLogger;
        projectInfoLabel.setIconTextGap(6);
        refreshTargetsBtn.setIcon(AllIcons.Actions.Refresh);
        setTitle("ZAFrida Project Settings");
        setOKButtonText("Save");
        targetGroup.add(manualTargetRadio);
        targetGroup.add(selectTargetRadio);
        init();
        manualTargetRadio.setSelected(true);
        loadFromProject();
        bindActions();
    }

    @Override
    protected @Nullable JComponent createCenterPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints labelC = new GridBagConstraints();
        labelC.gridx = 0;
        labelC.insets = new Insets(6, 8, 6, 8);
        labelC.anchor = GridBagConstraints.WEST;

        GridBagConstraints fieldC = new GridBagConstraints();
        fieldC.gridx = 1;
        fieldC.weightx = 1;
        fieldC.fill = GridBagConstraints.HORIZONTAL;
        fieldC.insets = new Insets(6, 8, 6, 8);

        int row = 0;
        labelC.gridy = row;
        fieldC.gridy = row;
        panel.add(new JLabel("Project"), labelC);
        panel.add(projectInfoLabel, fieldC);

        row++;
        labelC.gridy = row;
        fieldC.gridy = row;
        panel.add(new JLabel("Python Environment (blank = IDE)"), labelC);
        panel.add(buildPythonEnvironmentRow(), fieldC);

        row++;
        labelC.gridy = row;
        fieldC.gridy = row;
        panel.add(new JLabel("Connection Mode"), labelC);
        panel.add(connectionModeCombo, fieldC);

        row++;
        labelC.gridy = row;
        fieldC.gridy = row;
        panel.add(new JLabel("Remote Host:Port"), labelC);
        panel.add(buildRemoteHostRow(), fieldC);

        row++;
        labelC.gridy = row;
        fieldC.gridy = row;
        panel.add(new JLabel("Target (package/bundle)"), labelC);
        panel.add(buildTargetPanel(), fieldC);

        row++;
        labelC.gridy = row;
        fieldC.gridy = row;
        panel.add(new JLabel("Scope"), labelC);
        panel.add(scopeCombo, fieldC);

        return panel;
    }

    private JPanel buildPythonEnvironmentRow() {
        JPanel row = new JPanel(new BorderLayout(8, 0));
        pythonEnvironmentCombo.setEditable(true);
        pythonEnvironmentCombo.setPrototypeDisplayValue("/Users/example/.virtualenvs/frida-17/bin/python");
        pythonEnvironmentCombo.addItem("");
        pythonEnvironmentCombo.setToolTipText(
                "Blank uses the current PyCharm project interpreter. "
                        + "Supports local system/pyenv, venv/virtualenv, Conda, uv, Poetry, Pipenv, and Hatch environments."
        );
        useProjectPythonBtn.setToolTipText("Use the current PyCharm project interpreter");
        row.add(pythonEnvironmentCombo, BorderLayout.CENTER);

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actions.add(browsePythonEnvironmentBtn);
        actions.add(useProjectPythonBtn);
        actions.add(testPythonEnvironmentBtn);
        row.add(actions, BorderLayout.EAST);
        return row;
    }

    private JPanel buildTargetPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints rc = new GridBagConstraints();
        rc.gridx = 0;
        rc.gridy = 0;
        rc.insets = new Insets(0, 0, 4, 0);
        rc.anchor = GridBagConstraints.WEST;
        panel.add(manualTargetRadio, rc);

        manualTargetField.setColumns(24);
        rc.gridx = 1;
        rc.weightx = 1;
        rc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(manualTargetField, rc);

        rc.gridx = 0;
        rc.gridy = 1;
        rc.weightx = 0;
        rc.fill = GridBagConstraints.NONE;
        panel.add(selectTargetRadio, rc);

        rc.gridx = 1;
        rc.weightx = 1;
        rc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(buildTargetSelectRow(), rc);

        return panel;
    }

    private JPanel buildTargetSelectRow() {
        JPanel row = new JPanel(new BorderLayout(8, 0));
        targetCombo.setEditable(false);
        targetCombo.setPrototypeDisplayValue("com.example.app.package");
        row.add(targetCombo, BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actions.add(refreshTargetsBtn);
        row.add(actions, BorderLayout.EAST);
        return row;
    }

    private JPanel buildRemoteHostRow() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        remoteHostField.setColumns(16);
        remotePortField.setColumns(6);
        remoteHostField.getEmptyText().setText("127.0.0.1");
        remotePortField.getEmptyText().setText("14725");
        row.add(remoteHostField);
        row.add(new JLabel(":"));
        row.add(remotePortField);
        return row;
    }

    private void bindActions() {
        refreshTargetsBtn.addActionListener(e -> refreshTargets());
        browsePythonEnvironmentBtn.addActionListener(e -> browsePythonEnvironment());
        useProjectPythonBtn.addActionListener(e -> pythonEnvironmentCombo.getEditor().setItem(""));
        testPythonEnvironmentBtn.addActionListener(e -> testPythonEnvironment());
        scopeCombo.addActionListener(e -> {
            if (selectTargetRadio.isSelected()) {
                refreshTargets();
            }
        });

        manualTargetRadio.addActionListener(e -> updateTargetModeUi());
        selectTargetRadio.addActionListener(e -> {
            updateTargetModeUi();
            refreshTargets();
        });

        connectionModeCombo.addActionListener(e -> updateConnectionUi());
    }

    private void loadFromProject() {
        activeProject = projectManager.getActiveProject();
        updateProjectInfo();
        activeProjectConfig = null;
        if (activeProject == null) {
            connectionModeCombo.setEnabled(false);
            remoteHostField.setEnabled(false);
            remotePortField.setEnabled(false);
            scopeCombo.setEnabled(false);
            manualTargetField.setEnabled(false);
            targetCombo.setEnabled(false);
            refreshTargetsBtn.setEnabled(false);
            manualTargetRadio.setEnabled(false);
            selectTargetRadio.setEnabled(false);
            setPythonEnvironmentControlsEnabled(false);
            return;
        }
        setPythonEnvironmentControlsEnabled(false);
        ModalityState modality = ModalityState.stateForComponent(projectInfoLabel);
        projectManager.loadProjectConfigAsync(activeProject, cfg -> {
            activeProjectConfig = cfg;
            setPythonEnvironmentControlsEnabled(true);
            setPythonEnvironmentPath(cfg.pythonEnvironmentPath);
            connectionModeCombo.setEnabled(true);
            manualTargetRadio.setEnabled(true);
            selectTargetRadio.setEnabled(true);
            scopeCombo.setSelectedItem(cfg.processScope);
            setTargetText(cfg.lastTarget);
            if (cfg.connectionMode != null) {
                connectionModeCombo.setSelectedItem(cfg.connectionMode);
            } else {
                connectionModeCombo.setSelectedItem(FridaConnectionMode.USB);
            }

            ZaFridaSettingsState st = ApplicationManager.getApplication()
                    .getService(ZaFridaSettingsService.class)
                    .getState();
            String host;
            if (ZaStrUtil.isNotBlank(cfg.remoteHost)) {
                host = cfg.remoteHost;
            } else {
                host = ZaFridaNetUtil.normalizeHost(st.defaultRemoteHost);
            }
            if (host.isEmpty()) {
                host = ZaFridaNetUtil.LOOPBACK_HOST;
            }
            int port;
            if (cfg.remotePort > 0) {
                port = cfg.remotePort;
            } else {
                port = ZaFridaNetUtil.defaultPort(st.defaultRemotePort);
            }
            remoteHostField.setText(host);
            remotePortField.setText(String.valueOf(port));

            manualTargetRadio.setSelected(cfg.targetManual);
            selectTargetRadio.setSelected(!cfg.targetManual);

            updateConnectionUi();
            updateTargetModeUi();
            if (selectTargetRadio.isSelected()) {
                refreshTargets();
            }
        }, modality);
        loadReusablePythonEnvironments(modality);
    }

    private void setPythonEnvironmentControlsEnabled(boolean enabled) {
        pythonEnvironmentCombo.setEnabled(enabled);
        browsePythonEnvironmentBtn.setEnabled(enabled);
        useProjectPythonBtn.setEnabled(enabled);
        testPythonEnvironmentBtn.setEnabled(enabled);
    }

    private void loadReusablePythonEnvironments(@NotNull ModalityState modality) {
        projectManager.listPythonEnvironmentPathsAsync(this::addPythonEnvironmentOptions, modality);
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            List<String> interpreters = ProjectPythonEnvResolver.listIdeInterpreterPaths(project);
            ApplicationManager.getApplication().invokeLater(
                    () -> addPythonEnvironmentOptions(interpreters),
                    modality
            );
        });
    }

    private void addPythonEnvironmentOptions(@NotNull List<String> paths) {
        String selectedPath = getPythonEnvironmentPath();
        LinkedHashSet<String> options = new LinkedHashSet<>();
        options.add("");
        int itemCount = pythonEnvironmentCombo.getItemCount();
        for (int index = 0; index < itemCount; index++) {
            String item = pythonEnvironmentCombo.getItemAt(index);
            if (ZaStrUtil.isNotBlank(item)) {
                options.add(item.trim());
            }
        }
        for (String path : paths) {
            if (ZaStrUtil.isNotBlank(path)) {
                options.add(path.trim());
            }
        }

        pythonEnvironmentCombo.removeAllItems();
        for (String option : options) {
            pythonEnvironmentCombo.addItem(option);
        }
        pythonEnvironmentCombo.getEditor().setItem(selectedPath);
    }

    private void browsePythonEnvironment() {
        FileChooserDescriptor descriptor = new FileChooserDescriptor(true, true, false, false, false, false)
                .withTitle("Select Python Interpreter or Environment")
                .withDescription("Select a Python executable or a local environment directory");
        VirtualFile initial = resolvePythonEnvironmentSelection();
        VirtualFile selected = FileChooser.chooseFile(descriptor, project, initial);
        if (selected != null) {
            setPythonEnvironmentPath(selected.getPath());
        }
    }

    private void testPythonEnvironment() {
        String configuredPath = getPythonEnvironmentPath();
        ModalityState modality = ModalityState.stateForComponent(pythonEnvironmentCombo);
        int testGeneration = ++pythonValidationGeneration;
        testPythonEnvironmentBtn.setEnabled(false);
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                PythonEnvInfo environment;
                if (configuredPath.isEmpty()) {
                    environment = ProjectPythonEnvResolver.resolveIdeProject(project);
                } else {
                    environment = ProjectPythonEnvResolver.resolveConfiguredPath(configuredPath);
                }
                if (environment == null) {
                    throw new PythonEnvResolutionException("PyCharm project Python interpreter was not found");
                }
                String version = fridaCliService.detectFridaPythonVersion(environment);
                ApplicationManager.getApplication().invokeLater(() -> {
                    if (testGeneration != pythonValidationGeneration || project.isDisposed()) {
                        return;
                    }
                    testPythonEnvironmentBtn.setEnabled(true);
                    if (!configuredPath.equals(getPythonEnvironmentPath())) {
                        return;
                    }
                    Messages.showInfoMessage(
                            project,
                            String.format("Frida %s\nPython: %s", version, environment.getPythonHome()),
                            "Python Environment"
                    );
                }, modality);
            } catch (RuntimeException e) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    if (testGeneration != pythonValidationGeneration || project.isDisposed()) {
                        return;
                    }
                    testPythonEnvironmentBtn.setEnabled(true);
                    if (!configuredPath.equals(getPythonEnvironmentPath())) {
                        return;
                    }
                    String message = e.getMessage();
                    if (ZaStrUtil.isBlank(message)) {
                        message = e.getClass().getSimpleName();
                    }
                    logError(String.format("[ZAFrida] Python environment test failed: %s", message));
                    Messages.showErrorDialog(project, message, "Python Environment Test Failed");
                }, modality);
            }
        });
    }

    private @Nullable VirtualFile resolvePythonEnvironmentSelection() {
        String path = getPythonEnvironmentPath();
        if (path.isEmpty()) {
            return ProjectUtil.guessProjectDir(project);
        }
        VirtualFile selected = LocalFileSystem.getInstance().findFileByPath(path);
        if (selected != null) {
            return selected;
        }
        return ProjectUtil.guessProjectDir(project);
    }

    private void setPythonEnvironmentPath(@Nullable String path) {
        String normalized = "";
        if (path != null) {
            normalized = path.trim();
        }
        pythonEnvironmentCombo.getEditor().setItem(normalized);
    }

    private @NotNull String getPythonEnvironmentPath() {
        Object value = pythonEnvironmentCombo.getEditor().getItem();
        if (value == null) {
            return "";
        }
        return value.toString().trim();
    }

    private void updateProjectInfo() {
        if (activeProject == null) {
            projectInfoLabel.setIcon(null);
            projectInfoLabel.setText("No active project");
            projectInfoLabel.setToolTipText("No active project");
            return;
        }
        projectInfoLabel.setIcon(ZaFridaIcons.forPlatform(activeProject.getPlatform()));
        projectInfoLabel.setText(activeProject.getName());
        projectInfoLabel.setToolTipText(String.format("Platform: %s", activeProject.getPlatform().name()));
    }

    private void refreshTargets() {
        if (!selectTargetRadio.isSelected()) {
            return;
        }
        int refreshGeneration = ++targetRefreshGeneration;
        FridaDevice device = resolveDeviceForTargets();
        if (device == null) {
            Messages.showWarningDialog(project, "Select a device first in the Run panel.", "ZAFrida");
            logError("[ZAFrida] Select a device first in the Run panel.");
            return;
        }
        FridaProcessScope scope = (FridaProcessScope) scopeCombo.getSelectedItem();
        if (scope == null) {
            scope = FridaProcessScope.RUNNING_APPS;
        }

        // 该对话框是 Modal 的：如果直接 invokeLater（默认 NON_MODAL），更新 UI 的 Runnable 会被阻塞，
        // 进而出现 processes 明明有数据但 targetCombo 不刷新的现象。
        final ModalityState modality = ModalityState.stateForComponent(targetCombo);

        refreshTargetsBtn.setEnabled(false);
        FridaProcessScope finalScope = scope;
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                List<FridaProcess> processes = fridaCliService.listProcesses(project, device, finalScope);
                ApplicationManager.getApplication().invokeLater(() -> {
                    if (refreshGeneration != targetRefreshGeneration
                            || project.isDisposed()
                            || !selectTargetRadio.isSelected()) {
                        return;
                    }
                    targetCombo.removeAllItems();
                    for (FridaProcess p : processes) {
                        String label = targetLabel(p);
                        if (ZaStrUtil.isNotBlank(label)) {
                            targetCombo.addItem(label);
                        }
                    }
                    refreshTargetsBtn.setEnabled(true);
                }, modality);
            } catch (Throwable t) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    if (refreshGeneration != targetRefreshGeneration || project.isDisposed()) {
                        return;
                    }
                    refreshTargetsBtn.setEnabled(true);
                    logError(String.format("[ZAFrida] Load targets failed: %s", t.getMessage()));
                    Messages.showWarningDialog(project, String.format("Load targets failed: %s", t.getMessage()), "ZAFrida");
                }, modality);
            }
        });
    }

    @Override
    protected void doOKAction() {
        if (activeProject == null) {
            super.doOKAction();
            return;
        }
        String portError = validateRemotePort();
        if (portError != null) {
            setErrorText(portError, remotePortField);
            return;
        }
        setErrorText(null, remotePortField);
        String configuredPath = getPythonEnvironmentPath();
        if (configuredPath.isEmpty()) {
            saveProjectAndClose();
            return;
        }

        int validationGeneration = ++pythonValidationGeneration;
        ModalityState modality = ModalityState.stateForComponent(pythonEnvironmentCombo);
        setOKActionEnabled(false);
        setErrorText(null, pythonEnvironmentCombo);
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            String validationError = null;
            try {
                ProjectPythonEnvResolver.resolveConfiguredPath(configuredPath);
            } catch (PythonEnvResolutionException e) {
                validationError = e.getMessage();
            }

            String finalValidationError = validationError;
            ApplicationManager.getApplication().invokeLater(() -> {
                if (validationGeneration != pythonValidationGeneration || project.isDisposed()) {
                    return;
                }
                setOKActionEnabled(true);
                if (!configuredPath.equals(getPythonEnvironmentPath())) {
                    return;
                }
                if (finalValidationError != null) {
                    setErrorText(finalValidationError, pythonEnvironmentCombo);
                    return;
                }
                saveProjectAndClose();
            }, modality);
        });
    }

    private void saveProjectAndClose() {
        ZaFridaFridaProject projectToSave = activeProject;
        if (projectToSave == null) {
            return;
        }
        FridaProcessScope scope = (FridaProcessScope) scopeCombo.getSelectedItem();
        String target = getTargetText();
        FridaConnectionMode connectionMode = (FridaConnectionMode) connectionModeCombo.getSelectedItem();
        HostPort hostPort = resolveHostPortForSave();
        String pythonEnvironmentPath = getPythonEnvironmentPath();
        boolean targetManual = manualTargetRadio.isSelected();

        int saveGeneration = ++pythonValidationGeneration;
        setOKActionEnabled(false);
        projectManager.updateProjectConfigAsync(projectToSave, cfg -> {
            if (scope != null) {
                cfg.processScope = scope;
            } else {
                cfg.processScope = FridaProcessScope.RUNNING_APPS;
            }
            if (target.isEmpty()) {
                cfg.lastTarget = null;
            } else {
                cfg.lastTarget = target;
            }
            cfg.targetManual = targetManual;
            if (connectionMode != null) {
                cfg.connectionMode = connectionMode;
            } else {
                cfg.connectionMode = FridaConnectionMode.USB;
            }
            cfg.remoteHost = hostPort.host;
            cfg.remotePort = hostPort.port;
            cfg.pythonEnvironmentPath = pythonEnvironmentPath;
        }, () -> {
            if (saveGeneration != pythonValidationGeneration) {
                return;
            }
            setOKActionEnabled(true);
            closeAfterSuccessfulSave();
        }, error -> {
            if (saveGeneration != pythonValidationGeneration) {
                return;
            }
            setOKActionEnabled(true);
            String message = error.getMessage();
            if (ZaStrUtil.isBlank(message)) {
                message = error.getClass().getSimpleName();
            }
            logError(String.format("[ZAFrida] Save project settings failed: %s", message));
            setErrorText(message, pythonEnvironmentCombo);
        });
    }

    private void closeAfterSuccessfulSave() {
        super.doOKAction();
    }

    @Override
    public void doCancelAction() {
        pythonValidationGeneration++;
        targetRefreshGeneration++;
        super.doCancelAction();
    }

    private String getTargetText() {
        if (manualTargetRadio.isSelected()) {
            String target = manualTargetField.getText();
            if (target == null) {
                return "";
            }
            return target.trim();
        }
        Object selected = targetCombo.getSelectedItem();
        if (selected == null) {
            return "";
        }
        return selected.toString().trim();
    }

    private void setTargetText(@Nullable String value) {
        String normalizedValue = "";
        if (value != null) {
            normalizedValue = value.trim();
        }
        manualTargetField.setText(normalizedValue);
        if (ZaStrUtil.isBlank(value)) {
            targetCombo.setSelectedItem(null);
            return;
        }
        targetCombo.setSelectedItem(value);
    }

    private void updateTargetModeUi() {
        boolean manual = !selectTargetRadio.isSelected();
        manualTargetField.setEnabled(manual);
        targetCombo.setEnabled(!manual);
        refreshTargetsBtn.setEnabled(!manual);
        scopeCombo.setEnabled(!manual);
    }

    private void updateConnectionUi() {
        FridaConnectionMode mode = (FridaConnectionMode) connectionModeCombo.getSelectedItem();
        boolean remote = mode == FridaConnectionMode.REMOTE || mode == FridaConnectionMode.GADGET;
        remoteHostField.setEnabled(remote);
        remotePortField.setEnabled(remote);
    }

    private @Nullable FridaDevice resolveDeviceForTargets() {
        FridaConnectionMode mode = (FridaConnectionMode) connectionModeCombo.getSelectedItem();
        if (mode == FridaConnectionMode.REMOTE || mode == FridaConnectionMode.GADGET) {
            HostPort hostPort = resolveHostPortForSave();
            String host = String.format("%s:%s", hostPort.host, hostPort.port);
            String type = "remote";
            String name = "Remote";
            if (mode == FridaConnectionMode.GADGET) {
                type = "gadget";
                name = "Gadget";
            }
            return new FridaDevice(String.format("%s:%s", type, host), type, name, FridaDeviceMode.HOST, host);
        }

        FridaDevice device = deviceSupplier.get();
        if (device != null) {
            return device;
        }

        if (activeProject != null) {
            ZaFridaProjectConfig cfg = activeProjectConfig;
            if (cfg != null) {
                if (ZaStrUtil.isNotBlank(cfg.lastDeviceHost)) {
                    return new FridaDevice(String.format("remote:%s", cfg.lastDeviceHost), "remote", "Remote", FridaDeviceMode.HOST, cfg.lastDeviceHost);
                }
                if (ZaStrUtil.isNotBlank(cfg.lastDeviceId)) {
                    return new FridaDevice(cfg.lastDeviceId, "device", cfg.lastDeviceId, FridaDeviceMode.DEVICE_ID, null);
                }
            }
        }
        return null;
    }

    private HostPort resolveHostPortForSave() {
        ZaFridaSettingsState st = ApplicationManager.getApplication()
                .getService(ZaFridaSettingsService.class)
                .getState();
        String host = ZaFridaNetUtil.normalizeHost(remoteHostField.getText());
        if (host.isEmpty()) {
            host = ZaFridaNetUtil.normalizeHost(st.defaultRemoteHost);
        }
        if (host.isEmpty()) {
            host = ZaFridaNetUtil.LOOPBACK_HOST;
        }

        int port = parsePort(remotePortField.getText());
        if (port <= 0) {
            port = ZaFridaNetUtil.defaultPort(st.defaultRemotePort);
        }
        return new HostPort(host, port);
    }

    private static int parsePort(@Nullable String portText) {
        if (ZaStrUtil.isBlank(portText)) {
            return 0;
        }
        try {
            int value = Integer.parseInt(portText.trim());
            if (value <= 0 || value > 65_535) {
                return 0;
            }
            return value;
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private @Nullable String validateRemotePort() {
        FridaConnectionMode mode = (FridaConnectionMode) connectionModeCombo.getSelectedItem();
        if (mode != FridaConnectionMode.REMOTE && mode != FridaConnectionMode.GADGET) {
            return null;
        }
        String text = remotePortField.getText();
        if (ZaStrUtil.isBlank(text)) {
            return null;
        }
        if (parsePort(text) <= 0) {
            return "Remote port must be between 1 and 65535";
        }
        return null;
    }

    private static final class HostPort {
        private final String host;
        private final int port;

        private HostPort(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }

    private static @Nullable String targetLabel(@NotNull FridaProcess p) {
        if (ZaStrUtil.isNotBlank(p.getIdentifier())) {
            return p.getIdentifier();
        }
        if (ZaStrUtil.isNotBlank(p.getName())) {
            return p.getName();
        }
        return null;
    }

    private void logError(@NotNull String message) {
        if (errorLogger != null) {
            errorLogger.accept(message);
        }
    }
}
