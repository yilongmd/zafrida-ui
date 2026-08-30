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
import com.intellij.ui.TitledSeparator;
import com.intellij.ui.components.JBTextField;
import com.intellij.util.ui.JBUI;
import com.zafrida.ui.frida.FridaCliService;
import com.zafrida.ui.frida.FridaConnectionMode;
import com.zafrida.ui.frida.FridaDevice;
import com.zafrida.ui.frida.FridaDeviceMode;
import com.zafrida.ui.frida.FridaProcess;
import com.zafrida.ui.frida.FridaProcessScope;
import com.zafrida.ui.fridaproject.ZaFridaFridaProject;
import com.zafrida.ui.fridaproject.ZaFridaPlatform;
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
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Supplier;

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
    private final JLabel projectPlatformLabel = new JLabel("—");
    private final JLabel projectDirectoryLabel = new JLabel("—");

    private final ComboBox<String> pythonEnvironmentCombo = new ComboBox<>();
    private final JButton browsePythonEnvironmentBtn = new JButton("Browse...");
    private final JButton useProjectPythonBtn = new JButton("Default");
    private final JButton testPythonEnvironmentBtn = new JButton("Test");
    private final ZaFridaEnvironmentDetailsController environmentDetailsController;

    private @Nullable ZaFridaFridaProject activeProject;
    private @Nullable ZaFridaProjectConfig activeProjectConfig;
    private int pythonValidationGeneration;
    private int targetRefreshGeneration;
    private boolean updatingPythonEnvironmentSelection;

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
        this.environmentDetailsController = new ZaFridaEnvironmentDetailsController(project, fridaCliService);
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
        int row = 0;
        row = addSection(panel, row, "Project");
        row = addSettingsRow(panel, row, "Name", projectInfoLabel);
        row = addSettingsRow(panel, row, "Platform", projectPlatformLabel);
        row = addSettingsRow(panel, row, "Directory", projectDirectoryLabel);

        row = addSection(panel, row, "Python & Frida");
        row = addSettingsRow(panel, row, "Python Environment (blank = IDE)", buildPythonEnvironmentRow());
        row = addSettingsRow(panel, row, "Environment Source", environmentDetailsController.getSourceLabel());
        row = addSettingsRow(panel, row, "Resolved Interpreter", environmentDetailsController.getResolvedPythonLabel());
        row = addSettingsRow(panel, row, "Frida Version", environmentDetailsController.getFridaVersionLabel());

        row = addSection(panel, row, "Connection & Target");
        row = addSettingsRow(panel, row, "Connection Mode", connectionModeCombo);
        row = addSettingsRow(panel, row, "Remote Host:Port", buildRemoteHostRow());
        row = addSettingsRow(panel, row, "Target (package/bundle)", buildTargetPanel());
        addSettingsRow(panel, row, "Scope", scopeCombo);

        Dimension preferredSize = panel.getPreferredSize();
        int minimumWidth = JBUI.scale(760);
        if (preferredSize.width < minimumWidth) {
            preferredSize.width = minimumWidth;
        }
        panel.setPreferredSize(preferredSize);

        return panel;
    }

    private int addSection(@NotNull JPanel panel, int row, @NotNull String title) {
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.gridx = 0;
        constraints.gridy = row;
        constraints.gridwidth = 2;
        constraints.weightx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.insets = new Insets(JBUI.scale(8), JBUI.scale(8), JBUI.scale(2), JBUI.scale(8));
        panel.add(new TitledSeparator(title), constraints);
        return row + 1;
    }

    private int addSettingsRow(@NotNull JPanel panel,
                               int row,
                               @NotNull String label,
                               @NotNull JComponent component) {
        GridBagConstraints labelConstraints = new GridBagConstraints();
        labelConstraints.gridx = 0;
        labelConstraints.gridy = row;
        labelConstraints.anchor = GridBagConstraints.WEST;
        labelConstraints.insets = new Insets(JBUI.scale(5), JBUI.scale(8), JBUI.scale(5), JBUI.scale(12));
        panel.add(new JLabel(label), labelConstraints);

        GridBagConstraints componentConstraints = new GridBagConstraints();
        componentConstraints.gridx = 1;
        componentConstraints.gridy = row;
        componentConstraints.weightx = 1;
        componentConstraints.fill = GridBagConstraints.HORIZONTAL;
        componentConstraints.insets = new Insets(JBUI.scale(5), JBUI.scale(8), JBUI.scale(5), JBUI.scale(8));
        panel.add(component, componentConstraints);
        return row + 1;
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
        useProjectPythonBtn.addActionListener(e -> {
            setPythonEnvironmentPath("");
            markEnvironmentDetailsStale();
        });
        testPythonEnvironmentBtn.addActionListener(e -> testPythonEnvironment());
        pythonEnvironmentCombo.addActionListener(e -> {
            if (!updatingPythonEnvironmentSelection) {
                markEnvironmentDetailsStale();
            }
        });
        bindPythonEnvironmentEditorChanges();
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

    private void bindPythonEnvironmentEditorChanges() {
        Component editorComponent = pythonEnvironmentCombo.getEditor().getEditorComponent();
        if (!(editorComponent instanceof JTextField textField)) {
            return;
        }
        textField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent event) {
                handlePythonEnvironmentEditorChange();
            }

            @Override
            public void removeUpdate(DocumentEvent event) {
                handlePythonEnvironmentEditorChange();
            }

            @Override
            public void changedUpdate(DocumentEvent event) {
                handlePythonEnvironmentEditorChange();
            }
        });
    }

    private void handlePythonEnvironmentEditorChange() {
        if (!updatingPythonEnvironmentSelection) {
            markEnvironmentDetailsStale();
        }
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
            setEnvironmentDetailsUnavailable("No active project");
            return;
        }
        setPythonEnvironmentControlsEnabled(false);
        ModalityState modality = ModalityState.stateForComponent(projectInfoLabel);
        ZaFridaFridaProject projectToLoad = activeProject;
        projectManager.loadProjectUiStateAsync(
                projectToLoad,
                state -> applyLoadedProjectState(projectToLoad, state, modality),
                modality
        );
        loadReusablePythonEnvironments(modality);
    }

    private void applyLoadedProjectState(@NotNull ZaFridaFridaProject projectToLoad,
                                         @NotNull ZaFridaProjectManager.ProjectUiState state,
                                         @NotNull ModalityState modality) {
        if (!Objects.equals(projectToLoad, activeProject)
                || !Objects.equals(projectToLoad, projectManager.getActiveProject())) {
            return;
        }
        ZaFridaProjectConfig config = state.getConfig();
        activeProjectConfig = config;
        updateProjectDetails(state);
        applyProjectConfigToControls(config);
        inspectPythonEnvironment(config.pythonEnvironmentPath, modality, false);
    }

    private void applyProjectConfigToControls(@NotNull ZaFridaProjectConfig config) {
        setPythonEnvironmentControlsEnabled(true);
        setPythonEnvironmentPath(config.pythonEnvironmentPath);
        connectionModeCombo.setEnabled(true);
        manualTargetRadio.setEnabled(true);
        selectTargetRadio.setEnabled(true);
        scopeCombo.setSelectedItem(config.processScope);
        setTargetText(config.lastTarget);
        if (config.connectionMode != null) {
            connectionModeCombo.setSelectedItem(config.connectionMode);
        } else {
            connectionModeCombo.setSelectedItem(FridaConnectionMode.USB);
        }
        applyRemoteEndpoint(config);
        manualTargetRadio.setSelected(config.targetManual);
        selectTargetRadio.setSelected(!config.targetManual);
        updateConnectionUi();
        updateTargetModeUi();
        if (selectTargetRadio.isSelected()) {
            refreshTargets();
        }
    }

    private void applyRemoteEndpoint(@NotNull ZaFridaProjectConfig config) {
        ZaFridaSettingsState settingsState = ApplicationManager.getApplication()
                .getService(ZaFridaSettingsService.class)
                .getState();
        String host;
        if (ZaStrUtil.isNotBlank(config.remoteHost)) {
            host = config.remoteHost;
        } else {
            host = ZaFridaNetUtil.normalizeHost(settingsState.defaultRemoteHost);
        }
        if (host.isEmpty()) {
            host = ZaFridaNetUtil.LOOPBACK_HOST;
        }
        int port;
        if (config.remotePort > 0) {
            port = config.remotePort;
        } else {
            port = ZaFridaNetUtil.defaultPort(settingsState.defaultRemotePort);
        }
        remoteHostField.setText(host);
        remotePortField.setText(String.valueOf(port));
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

        updatingPythonEnvironmentSelection = true;
        try {
            pythonEnvironmentCombo.removeAllItems();
            for (String option : options) {
                pythonEnvironmentCombo.addItem(option);
            }
            pythonEnvironmentCombo.getEditor().setItem(selectedPath);
        } finally {
            updatingPythonEnvironmentSelection = false;
        }
    }

    private void browsePythonEnvironment() {
        FileChooserDescriptor descriptor = new FileChooserDescriptor(true, true, false, false, false, false)
                .withTitle("Select Python Interpreter or Environment")
                .withDescription("Select a Python executable or a local environment directory");
        VirtualFile initial = resolvePythonEnvironmentSelection();
        VirtualFile selected = FileChooser.chooseFile(descriptor, project, initial);
        if (selected != null) {
            setPythonEnvironmentPath(selected.getPath());
            markEnvironmentDetailsStale();
        }
    }

    private void testPythonEnvironment() {
        String configuredPath = getPythonEnvironmentPath();
        ModalityState modality = ModalityState.stateForComponent(pythonEnvironmentCombo);
        inspectPythonEnvironment(configuredPath, modality, true);
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
        updatingPythonEnvironmentSelection = true;
        try {
            pythonEnvironmentCombo.getEditor().setItem(normalized);
        } finally {
            updatingPythonEnvironmentSelection = false;
        }
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
            projectPlatformLabel.setText("—");
            projectDirectoryLabel.setText("—");
            projectDirectoryLabel.setToolTipText(null);
            return;
        }
        projectInfoLabel.setIcon(ZaFridaIcons.forPlatform(activeProject.getPlatform()));
        projectInfoLabel.setText(activeProject.getName());
        projectInfoLabel.setToolTipText(String.format("Platform: %s", activeProject.getPlatform().name()));
        projectPlatformLabel.setText(formatPlatform(activeProject));
        projectDirectoryLabel.setText(activeProject.getRelativeDir());
        projectDirectoryLabel.setToolTipText(activeProject.getRelativeDir());
    }

    private void updateProjectDetails(@NotNull ZaFridaProjectManager.ProjectUiState state) {
        ZaFridaFridaProject currentProject = activeProject;
        if (currentProject == null) {
            return;
        }
        VirtualFile projectDirectory = state.getProjectDir();
        if (projectDirectory == null) {
            projectDirectoryLabel.setText(String.format("%s (not found)", currentProject.getRelativeDir()));
            projectDirectoryLabel.setToolTipText("Project directory was not found");
            return;
        }
        projectDirectoryLabel.setText(projectDirectory.getPath());
        projectDirectoryLabel.setToolTipText(projectDirectory.getPath());
    }

    private @NotNull String formatPlatform(@NotNull ZaFridaFridaProject fridaProject) {
        if (fridaProject.getPlatform() == ZaFridaPlatform.ANDROID) {
            return "Android";
        }
        return "iOS";
    }

    private void inspectPythonEnvironment(@NotNull String configuredPath,
                                          @NotNull ModalityState modality,
                                          boolean showResultDialog) {
        testPythonEnvironmentBtn.setEnabled(false);
        environmentDetailsController.inspect(configuredPath, modality, result -> {
            if (!configuredPath.equals(getPythonEnvironmentPath())) {
                return;
            }
            testPythonEnvironmentBtn.setEnabled(activeProject != null);
            if (showResultDialog) {
                showEnvironmentInspectionResult(result);
            }
        });
    }

    private void showEnvironmentInspectionResult(
            @NotNull ZaFridaEnvironmentDetailsController.InspectionResult result) {
        String errorMessage = result.getErrorMessage();
        if (ZaStrUtil.isNotBlank(errorMessage)) {
            logError(String.format("[ZAFrida] Python environment test failed: %s", errorMessage));
            Messages.showErrorDialog(project, errorMessage, "Python Environment Test Failed");
            return;
        }
        PythonEnvInfo environment = result.getEnvironment();
        String fridaVersion = result.getFridaVersion();
        if (environment == null || ZaStrUtil.isBlank(fridaVersion)) {
            return;
        }
        Messages.showInfoMessage(
                project,
                String.format(
                        "Frida %s\nPython: %s\nSource: %s",
                        fridaVersion,
                        environment.getPythonHome(),
                        ZaFridaEnvironmentDetailsController.environmentSourceText(environment)
                ),
                "Python Environment"
        );
    }

    private void markEnvironmentDetailsStale() {
        environmentDetailsController.markStale();
        testPythonEnvironmentBtn.setEnabled(activeProject != null);
    }

    private void setEnvironmentDetailsUnavailable(@Nullable String reason) {
        environmentDetailsController.setUnavailable(reason);
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
        environmentDetailsController.cancelPendingInspection();
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
