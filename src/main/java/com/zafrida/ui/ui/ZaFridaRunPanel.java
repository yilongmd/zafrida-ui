package com.zafrida.ui.ui;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.ide.util.PropertiesComponent;
import com.intellij.openapi.project.Project;
import com.zafrida.ui.adb.AdbService;
import com.zafrida.ui.api.ZaFridaLocalHttpApiService;
import com.zafrida.ui.diagnostics.EnvironmentDoctorDialog;
import com.intellij.icons.AllIcons;
import com.intellij.openapi.options.ShowSettingsUtil;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.ui.ComboBox;
import com.intellij.openapi.vfs.LocalFileSystem;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.ui.JBColor;
import com.intellij.ui.components.ActionLink;
import com.intellij.ui.components.JBLabel;
import com.intellij.ui.components.JBTextField;
import com.intellij.util.ui.JBUI;
import com.intellij.util.ui.UIUtil;
import com.zafrida.ui.frida.*;
import com.zafrida.ui.fridaproject.*;
import com.zafrida.ui.fridaproject.ui.CreateZaFridaProjectDialog;
import com.zafrida.ui.fridaproject.ui.ZaFridaProjectSettingsDialog;
import com.zafrida.ui.session.RunningSession;
import com.zafrida.ui.session.ZaFridaSessionService;
import com.zafrida.ui.session.ZaFridaSessionType;
import com.zafrida.ui.python.ProjectPythonEnvResolver;
import com.zafrida.ui.python.PythonEnvInfo;
import com.zafrida.ui.python.PythonEnvResolutionException;
import com.zafrida.ui.ui.components.ConnectionModePanel;
import com.zafrida.ui.ui.components.SearchableComboBoxPanel;
import com.zafrida.ui.ui.components.SimpleDocumentListener;
import com.zafrida.ui.ui.render.DeviceCellRenderer;
import com.zafrida.ui.util.ProjectFileUtil;
import com.zafrida.ui.util.ZaFridaNetUtil;
import com.zafrida.ui.util.ZaFridaIcons;
import com.zafrida.ui.util.ZaFridaNotifier;
import com.zafrida.ui.util.ZaFridaTextUtil;
import com.zafrida.ui.util.ZaStrUtil;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.settings.ZaFridaSettingsState;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.io.File;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Supplier;

public final class ZaFridaRunPanel extends JPanel implements Disposable {

    private static final Logger LOG = Logger.getInstance(ZaFridaRunPanel.class);
    private static final String ADVANCED_EXPANDED_KEY = "zafrida.session.advanced.expanded";
    private static final String TARGET_TOOLTIP = "Spawn/Attach uses package name";
    private static final String GADGET_TARGET_TOOLTIP =
            "Gadget mode attaches to the frontmost app (-F). Target is read-only here and only used by Force Stop / Open App; edit it in Project settings.";
    private static final String DEVICES_LOADING_SUMMARY = "Loading devices...";

    private final @NotNull Project project;
    private final @NotNull ZaFridaConsoleTabsPanel consoleTabsPanel;
    private final @NotNull ZaFridaConsolePanel runConsolePanel;
    private final @NotNull ZaFridaConsolePanel attachConsolePanel;
    private final @NotNull ZaFridaTemplatePanel templatePanel;

    private final @NotNull FridaCliService fridaCli;
    private final @NotNull ZaFridaSessionService sessionService;
    private final @NotNull AdbService adbService;
    private final @NotNull ZaFridaLocalHttpApiService localHttpApiService;

    private final ComboBox<FridaDevice> deviceCombo = new ComboBox<>();
    private final JButton refreshDevicesBtn = new JButton("");
    private final ConnectionModePanel connectionModePanel = new ConnectionModePanel();
    private final JBLabel routeSummaryLabel = new JBLabel();

    private final JBTextField runScriptField = new JBTextField();
    private final JButton locateRunScriptBtn = new JButton("");
    private final JButton chooseRunScriptBtn = new JButton("");
    private final JBTextField attachScriptField = new JBTextField();
    private final JButton locateAttachScriptBtn = new JButton("");
    private final JButton chooseAttachScriptBtn = new JButton("");

    private final JBTextField targetField = new JBTextField();

    private final JBTextField extraArgsField = new JBTextField();
    private final ActionLink advancedLink = new ActionLink("Advanced ▸");
    private final JLabel extraArgsLabel = new JLabel("Extra Args");
    private final JPanel extraArgsRow;

    private final JButton runBtn = new JButton("Run");
    private final JButton stopBtn = new JButton("Stop Run");
    private final JButton attachBtn = new JButton("Attach");
    private final JButton stopAttachBtn = new JButton("Stop Attach");
    private final JButton forceStopBtn = new JButton("");
    private final JButton openAppBtn = new JButton("");

    private final JLabel fridaVersionLabel = new JLabel("—");

    private @Nullable VirtualFile runScriptFile;
    private @Nullable VirtualFile attachScriptFile;
    private @Nullable VirtualFile activeProjectDir;
    private @Nullable ZaFridaFridaProject lastAppliedProject;
    private @Nullable PendingProjectAction pendingProjectAction;

    private volatile @Nullable String lastPrintedPythonEnvironment;
    private boolean warnedNoUsbDevices = false;
    private @Nullable String lastMissingDeviceId;
    private @Nullable String announcedDeviceSubstitution;
    private final Set<String> notifiedMissingDeviceIds = new HashSet<>();
    private boolean devicesLoading;
    private int explicitDeviceSelections;

    private final ZaFridaProjectManager fridaProjectManager;
    private final SearchableComboBoxPanel<ZaFridaFridaProject> fridaProjectSelector =
            new SearchableComboBoxPanel<>(p -> {
                if (p == null) {
                    return "";
                }
                return p.getName();
            });
    private final JLabel projectTypeIcon = new JLabel();
    private boolean updatingFridaProjectSelector = false;
    private boolean updatingDeviceCombo = false;
    private boolean updatingRunFields = false;
    private boolean advancedExpanded;
    private int activeProjectUiGeneration = 0;
    private int deviceReloadGeneration = 0;
    private boolean disposed;
    private final EnumSet<ZaFridaSessionType> stoppingSessions = EnumSet.noneOf(ZaFridaSessionType.class);


    public ZaFridaRunPanel(@NotNull Project project,
                           @NotNull ZaFridaConsoleTabsPanel consoleTabsPanel,
                           @NotNull ZaFridaTemplatePanel templatePanel) {
        super(new BorderLayout());
        this.project = project;
        this.consoleTabsPanel = consoleTabsPanel;
        this.runConsolePanel = consoleTabsPanel.getRunConsolePanel();
        this.attachConsolePanel = consoleTabsPanel.getAttachConsolePanel();
        this.templatePanel = templatePanel;

        this.fridaCli = ApplicationManager.getApplication().getService(FridaCliService.class);
        this.sessionService = project.getService(ZaFridaSessionService.class);
        this.adbService = ApplicationManager.getApplication().getService(AdbService.class);
        this.fridaProjectManager = project.getService(ZaFridaProjectManager.class);
        this.localHttpApiService = project.getService(ZaFridaLocalHttpApiService.class);
        this.extraArgsRow = buildExtraRow();


        JPanel form = new JPanel(new GridBagLayout());

        int row = 0;
        row = addRow(form, row, new JLabel("Project"), buildFridaProjectRow());
        row = addRow(form, row, new JLabel("Device"), buildDeviceRow());
        row = addRow(form, row, new JLabel("Mode"), connectionModePanel);
        row = addHintRow(form, row, routeSummaryLabel);
        row = addRow(form, row, new JLabel("Run Script"), buildRunScriptRow());
        row = addRow(form, row, new JLabel("Attach Script"), buildAttachScriptRow());
        row = addRow(form, row, new JLabel("Target"), buildTargetRow());
        row = addRow(form, row, new JLabel(""), buildAdvancedRow());
        row = addRow(form, row, extraArgsLabel, extraArgsRow);
        row = addRow(form, row, new JLabel(""), buildButtonsRow());

        add(form, BorderLayout.NORTH);

        boolean storedAdvancedExpanded = PropertiesComponent.getInstance(project)
                .getBoolean(ADVANCED_EXPANDED_KEY, false);
        setAdvancedExpanded(storedAdvancedExpanded, false);

        initUiState();
        bindActions();
        subscribeToFridaProjectChanges();
        reloadFridaProjectsIntoUi();
        applyActiveFridaProjectToUi(fridaProjectManager.getActiveProject());
        localHttpApiService.bindRunPanel(this);
    }

    private void initUiState() {
        deviceCombo.setRenderer(new DeviceCellRenderer());
        runScriptField.setEditable(false);
        attachScriptField.setEditable(false);
        runScriptField.setHorizontalAlignment(JTextField.TRAILING);
        attachScriptField.setHorizontalAlignment(JTextField.TRAILING);

        extraArgsField.getEmptyText().setText("--realm=emulated or -l extra.js");
        extraArgsField.setToolTipText("Extra Frida CLI args, e.g. --realm=emulated or -l path/to/extra.js");
        advancedLink.setToolTipText("Show or hide advanced Frida options");
        advancedLink.getAccessibleContext().setAccessibleName("Toggle advanced Frida options");
        projectTypeIcon.setToolTipText("Project platform");

        targetField.setToolTipText(TARGET_TOOLTIP);
        deviceCombo.setToolTipText("Physical device: used by Frida in USB mode and by adb (forward, Force Stop, Open App) in every mode");

        routeSummaryLabel.setFont(JBUI.Fonts.smallFont());
        routeSummaryLabel.setForeground(UIUtil.getContextHelpForeground());
        // GridBagLayout 在首选尺寸放不下时会整体退回最小尺寸；摘要可能很长，
        // 固定它的首选/最小宽度，避免一行提示把整张表单撑宽，超出部分由 JLabel 自行省略。
        routeSummaryLabel.setText(DEVICES_LOADING_SUMMARY);
        Dimension compactSummarySize = new Dimension(JBUI.scale(120), routeSummaryLabel.getPreferredSize().height);
        routeSummaryLabel.setMinimumSize(compactSummarySize);
        routeSummaryLabel.setPreferredSize(compactSummarySize);

        refreshDevicesBtn.setIcon(AllIcons.Actions.Refresh);
        refreshDevicesBtn.setToolTipText("Refresh devices (starts the ADB server if it is not running)");
        locateRunScriptBtn.setIcon(AllIcons.General.Locate);
        locateRunScriptBtn.setToolTipText("Locate run script in Project View");
        chooseRunScriptBtn.setIcon(AllIcons.Actions.MenuOpen);
        chooseRunScriptBtn.setToolTipText("Choose run script");
        locateAttachScriptBtn.setIcon(AllIcons.General.Locate);
        locateAttachScriptBtn.setToolTipText("Locate attach script in Project View");
        chooseAttachScriptBtn.setIcon(AllIcons.Actions.MenuOpen);
        chooseAttachScriptBtn.setToolTipText("Choose attach script");
        runBtn.setIcon(AllIcons.Actions.Execute);
        runBtn.setToolTipText("Start Run session");
        attachBtn.setIcon(AllIcons.Actions.Execute);
        attachBtn.setToolTipText("Start Attach session");
        stopBtn.setIcon(AllIcons.Actions.Suspend);
        stopBtn.setToolTipText("Stop Run session");
        stopAttachBtn.setIcon(AllIcons.Actions.Suspend);
        stopAttachBtn.setToolTipText("Stop Attach session");
        forceStopBtn.setIcon(AllIcons.Actions.Cancel);
        forceStopBtn.setToolTipText("Force Stop App (adb force-stop)");
        openAppBtn.setIcon(AllIcons.Actions.Execute);
        openAppBtn.setToolTipText("Open App (adb)");
        fridaVersionLabel.setToolTipText("Frida version has not been detected for the current Python environment");
        updateRunningState();
    }

    private JPanel buildFridaProjectRow() {
        JPanel row = new JPanel(new BorderLayout(JBUI.scale(6), 0));
        JPanel metadata = new JPanel(new BorderLayout());
        JPanel metadataContent = new JPanel(new FlowLayout(FlowLayout.LEFT, JBUI.scale(6), 0));
        metadataContent.add(projectTypeIcon);
        metadataContent.add(fridaVersionLabel);
        metadata.add(metadataContent, BorderLayout.SOUTH);
        row.add(fridaProjectSelector, BorderLayout.CENTER);
        row.add(metadata, BorderLayout.EAST);
        return row;
    }

    private void bindActions() {
        refreshDevicesBtn.addActionListener(e -> reloadDevicesAsync());

        runBtn.addActionListener(e -> runFrida());
        attachBtn.addActionListener(e -> attachFrida());
        stopBtn.addActionListener(e -> stopRunSession());
        stopAttachBtn.addActionListener(e -> stopAttachSession());
        forceStopBtn.addActionListener(e -> forceStopApp());
        openAppBtn.addActionListener(e -> openApp());
        advancedLink.addActionListener(event -> setAdvancedExpanded(!advancedExpanded, true));

        deviceCombo.addActionListener(e -> {
            if (updatingDeviceCombo) {
                return;
            }
            FridaDevice selected = (FridaDevice) deviceCombo.getSelectedItem();
            explicitDeviceSelections++;
            persistSelectedDevice(selected);
            updateRouteSummary();
        });

        connectionModePanel.setListener(new ConnectionModePanel.Listener() {
            @Override
            public void onConnectionChanged(@NotNull FridaConnectionMode mode, @NotNull String host, int port) {
                persistConnection(mode, host, port);
            }

            @Override
            public void onInvalidEndpoint(@NotNull String text) {
                ZaFridaNotifier.warn(project, "ZAFrida",
                        String.format("Invalid Frida endpoint: %s. Expected host:port.", text));
            }
        });

        fridaProjectSelector.addActionListener(e -> {
            if (updatingFridaProjectSelector) {
                return;
            }
            fridaProjectManager.setActiveProjectAsync(fridaProjectSelector.getSelectedItem());
        });

        extraArgsField.getDocument().addDocumentListener(new SimpleDocumentListener(this::persistExtraArgs));

        chooseRunScriptBtn.addActionListener(e -> {
            ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
            VirtualFile initial = resolveInitialScriptSelection(runScriptFile, runScriptField.getText(), activeProjectDir);
            VirtualFile file = chooseRunScriptFile(initial);
            if (file == null) {
                return;
            }

            setRunScriptFile(file);

            if (active != null) {
                fridaProjectManager.updateMainScriptPathAsync(active, file);
            }
        });

        chooseAttachScriptBtn.addActionListener(e -> {
            ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
            VirtualFile initial = resolveInitialScriptSelection(attachScriptFile, attachScriptField.getText(), activeProjectDir);
            VirtualFile file = chooseAttachScriptFile(initial);
            if (file == null) {
                return;
            }

            setAttachScriptFile(file);

            if (active != null) {
                fridaProjectManager.updateAttachScriptPathAsync(active, file);
            }
        });

        locateRunScriptBtn.addActionListener(e -> locateRunScriptInProjectView());
        locateAttachScriptBtn.addActionListener(e -> locateAttachScriptInProjectView());

        consoleTabsPanel.addTabChangeListener(e -> updateRunningState());

    }

    private void subscribeToFridaProjectChanges() {
        // 连接绑定到面板生命周期，ToolWindow 释放时自动退订。
        project.getMessageBus().connect(this).subscribe(ZaFridaProjectManager.TOPIC, new ZaFridaProjectListener() {
            @Override
            public void onActiveProjectChanged(@Nullable ZaFridaFridaProject newProject) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    reloadFridaProjectsIntoUi();
                    applyActiveFridaProjectToUi(newProject);
                });
            }
        });
    }

    private void reloadFridaProjectsIntoUi() {
        updatingFridaProjectSelector = true;
        try {
            List<ZaFridaFridaProject> list = fridaProjectManager.listProjects();
            fridaProjectSelector.setItems(list);
            fridaProjectSelector.setSelectedItem(fridaProjectManager.getActiveProject());

            fridaProjectSelector.setEnabled(true);
        } finally {
            updatingFridaProjectSelector = false;
        }
    }

    private void applyActiveFridaProjectToUi(@Nullable ZaFridaFridaProject active) {
        int generation = ++activeProjectUiGeneration;
        fridaCli.clearDetectedProjectVersion(project);
        lastPrintedPythonEnvironment = null;
        setFridaVersionLabel("…", "Detecting Frida version for the current Python environment");
        updatingFridaProjectSelector = true;
        try {
            fridaProjectSelector.setSelectedItem(active);
        } finally {
            updatingFridaProjectSelector = false;
        }

        updateProjectTypeIcon(active);
        ZaFridaPlatform platform = null;
        if (active != null) {
            platform = active.getPlatform();
        }
        templatePanel.setCurrentPlatform(platform);

        if (active == null) {
            setFridaVersionLabel("—", "No active ZAFrida project");
            // 保留自由脚本模式下的临时输入。
            applyConnectionUi(null);
            activeProjectDir = null;
            lastAppliedProject = null;
            pendingProjectAction = null;
            reloadDevicesAsyncWithConfig(null);
            return;
        }

        fridaProjectManager.loadProjectUiStateAsync(active, state -> {
            if (disposed
                    || generation != activeProjectUiGeneration
                    || !Objects.equals(active, fridaProjectManager.getActiveProject())) {
                return;
            }
            ZaFridaProjectConfig cfg = state.getConfig();
            activeProjectDir = state.getProjectDir();

            updatingRunFields = true;
            try {
                String extraArgs = cfg.extraArgs;
                if (extraArgs == null) {
                    extraArgs = "";
                }
                extraArgsField.setText(extraArgs);
            } finally {
                updatingRunFields = false;
            }

            if (ZaStrUtil.isNotBlank(cfg.lastTarget)) {
                targetField.setText(cfg.lastTarget);
            } else {
                targetField.setText("");
            }

            applyConnectionUi(cfg);

            VirtualFile mainScript = state.getMainScriptFile();
            if (mainScript != null && !mainScript.isDirectory()) {
                setRunScriptFile(mainScript);
            } else {
                runScriptFile = null;
                setScriptPathText(runScriptField, "");
                templatePanel.setCurrentScriptFile(null);
                if (ZaStrUtil.isNotBlank(cfg.mainScript)) {
                    runConsolePanel.warn(String.format("[ZAFrida] Main script not found in project: %s", cfg.mainScript));
                }
            }

            VirtualFile attachScript = state.getAttachScriptFile();
            if (attachScript != null && !attachScript.isDirectory()) {
                setAttachScriptFile(attachScript);
            } else {
                attachScriptFile = null;
                setScriptPathText(attachScriptField, "");
                if (ZaStrUtil.isNotBlank(cfg.attachScript)) {
                    runConsolePanel.warn(String.format("[ZAFrida] Attach script not found in project: %s", cfg.attachScript));
                }
            }

            reloadDevicesAsyncWithConfig(cfg);
            lastAppliedProject = active;
            consumePendingProjectAction(active);
        });
    }

    private void updateProjectTypeIcon(@Nullable ZaFridaFridaProject active) {
        if (active == null) {
            projectTypeIcon.setIcon(null);
            projectTypeIcon.setToolTipText("No active project");
            return;
        }
        projectTypeIcon.setIcon(ZaFridaIcons.forPlatform(active.getPlatform()));
        projectTypeIcon.setToolTipText(String.format("Platform: %s", active.getPlatform().name()));
    }

    private void persistExtraArgs() {
        updateAdvancedLinkText();
        if (updatingRunFields) {
            return;
        }
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        if (active == null) {
            return;
        }
        String args = extraArgsField.getText();
        fridaProjectManager.updateProjectConfigAsync(active, c -> {
            if (args == null) {
                c.extraArgs = "";
            } else {
                c.extraArgs = args;
            }
        });
    }

    private @Nullable VirtualFile chooseRunScriptFile(@Nullable VirtualFile initialSelection) {
        ZaFridaSettingsState st = ApplicationManager.getApplication()
                .getService(ZaFridaSettingsService.class)
                .getState();
        if (st.useIdeScriptChooser) {
            return ProjectFileUtil.chooseFridaScriptFileInProject(project, initialSelection);
        }
        return ProjectFileUtil.chooseFridaScriptFile(project, initialSelection);
    }

    private @Nullable VirtualFile chooseAttachScriptFile(@Nullable VirtualFile initialSelection) {
        return chooseRunScriptFile(initialSelection);
    }

    private @Nullable VirtualFile resolveInitialScriptSelection(@Nullable VirtualFile cachedFile,
                                                                @Nullable String pathText,
                                                                @Nullable VirtualFile fallbackDir) {
        if (cachedFile != null && cachedFile.isValid()) {
            return cachedFile;
        }
        VirtualFile fromPath = resolveVirtualFileFromText(pathText);
        if (fromPath != null) {
            return fromPath;
        }
        if (fallbackDir != null && fallbackDir.isValid()) {
            return fallbackDir;
        }
        return null;
    }

    private @Nullable VirtualFile resolveVirtualFileFromText(@Nullable String pathText) {
        if (ZaStrUtil.isBlank(pathText)) {
            return null;
        }
        String path = pathText.trim();
        VirtualFile file = LocalFileSystem.getInstance().findFileByPath(path);
        if (file != null && file.isValid()) {
            return file;
        }
        String parentPath = new File(path).getParent();
        if (parentPath == null || parentPath.isEmpty()) {
            return null;
        }
        VirtualFile parent = LocalFileSystem.getInstance().findFileByPath(parentPath);
        if (parent != null && parent.isValid()) {
            return parent;
        }
        return null;
    }

    private void createNewFridaProject() {
        CreateZaFridaProjectDialog dialog = new CreateZaFridaProjectDialog(project);
        if (!dialog.showAndGet()) {
            return;
        }

        String name = dialog.getProjectName();
        if (name.isEmpty()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Project name is empty");
            return;
        }

        ZaFridaPlatform platform = dialog.getPlatform();

        fridaProjectManager.createAndActivateAsync(name, platform, created -> {
            reloadFridaProjectsIntoUi();
            applyActiveFridaProjectToUi(created);
            runConsolePanel.info(String.format("[ZAFrida] Created project: %s (%s)", created.getName(), created.getRelativeDir()));
        }, t -> {
            runConsolePanel.error(String.format("[ZAFrida] Create project failed: %s", t.getMessage()));
            ZaFridaNotifier.error(project, "ZAFrida", String.format("Create project failed: %s", t.getMessage()));
        });
    }

    private void openProjectSettings() {
        ZaFridaProjectSettingsDialog dialog = new ZaFridaProjectSettingsDialog(
                project,
                fridaProjectManager,
                fridaCli,
                () -> (FridaDevice) deviceCombo.getSelectedItem(),
                runConsolePanel::error
        );
        if (dialog.showAndGet()) {
            applyActiveFridaProjectToUi(fridaProjectManager.getActiveProject());
        }
    }

    private void openGlobalSettings() {
        ShowSettingsUtil.getInstance().showSettingsDialog(project, "ZAFrida");
        connectionModePanel.setEndpointPresets(buildEndpointPresets());
    }

    public void openNewProjectDialog() {
        createNewFridaProject();
    }

    public void openProjectSettingsDialog() {
        openProjectSettings();
    }

    public void openGlobalSettingsDialog() {
        openGlobalSettings();
    }

    public void openEnvironmentDoctorDialog() {
        Supplier<FridaDevice> supplier = new Supplier<FridaDevice>() {
            @Override
            public FridaDevice get() {
                return getSelectedDeviceForDiagnostics();
            }
        };
        EnvironmentDoctorDialog dialog = new EnvironmentDoctorDialog(project, supplier);
        dialog.show();
    }

    public void triggerRun() {
        if (!runBtn.isEnabled()) {
            return;
        }
        runFrida();
    }

    public void runWithRunScript(@NotNull VirtualFile file) {
        if (!file.isValid() || file.isDirectory()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Invalid script file");
            return;
        }
        setRunScriptFile(file);
        triggerRun();
    }

    public void runWithRunScriptAfterProjectSwitch(@NotNull ZaFridaFridaProject expectedProject,
                                                   @NotNull VirtualFile file) {
        if (!file.isValid() || file.isDirectory()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Invalid script file");
            return;
        }
        enqueueProjectAction(expectedProject, () -> {
            setRunScriptFile(file);
            triggerRun();
        });
    }

    public void triggerAttach() {
        if (!attachBtn.isEnabled()) {
            return;
        }
        attachFrida();
    }

    public void attachWithScript(@NotNull VirtualFile file) {
        if (!file.isValid() || file.isDirectory()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Invalid attach script file");
            return;
        }
        setAttachScriptFile(file);
        triggerAttach();
    }

    public void attachWithScriptAfterProjectSwitch(@NotNull ZaFridaFridaProject expectedProject,
                                                   @NotNull VirtualFile file) {
        if (!file.isValid() || file.isDirectory()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Invalid attach script file");
            return;
        }
        enqueueProjectAction(expectedProject, () -> {
            setAttachScriptFile(file);
            triggerAttach();
        });
    }

    private void enqueueProjectAction(@NotNull ZaFridaFridaProject expectedProject, @NotNull Runnable action) {
        if (expectedProject.equals(lastAppliedProject)) {
            action.run();
            return;
        }
        pendingProjectAction = new PendingProjectAction(expectedProject, action);
    }

    private void consumePendingProjectAction(@Nullable ZaFridaFridaProject active) {
        PendingProjectAction pending = pendingProjectAction;
        if (pending == null) {
            return;
        }
        if (active == null) {
            return;
        }
        if (!active.equals(pending.expectedProject)) {
            return;
        }
        pendingProjectAction = null;
        pending.action.run();
    }

    public void triggerStop() {
        if (!stopBtn.isEnabled()) {
            return;
        }
        stopRunSession();
    }

    public void triggerStopAttach() {
        if (!stopAttachBtn.isEnabled()) {
            return;
        }
        stopAttachSession();
    }

    public void triggerForceStop() {
        forceStopApp();
    }

    public void triggerOpenApp() {
        openApp();
    }

    public void refreshDevicesForApi() {
        reloadDevicesAsync();
    }

    public void refreshActiveProjectUiForApi() {
        applyActiveFridaProjectToUi(fridaProjectManager.getActiveProject());
    }

    public @Nullable FridaDevice getSelectedDeviceForApi() {
        return (FridaDevice) deviceCombo.getSelectedItem();
    }

    public boolean selectDeviceByIdForApi(@NotNull String deviceId) {
        String normalized = deviceId.trim();
        if (normalized.isEmpty()) {
            return false;
        }
        FridaDevice match = findConnectedComboDevice(normalized);
        if (match == null) {
            return false;
        }
        deviceCombo.setSelectedItem(match);
        return true;
    }

    public void selectDeviceForApi(@NotNull FridaDevice device) {
        FridaDevice selection;
        updatingDeviceCombo = true;
        try {
            selection = findConnectedComboDevice(device.getId());
            if (selection == null) {
                removeNotConnectedPlaceholder(device.getId());
                deviceCombo.addItem(device);
                selection = device;
            }
            deviceCombo.setSelectedItem(selection);
        } finally {
            updatingDeviceCombo = false;
        }
        explicitDeviceSelections++;
        persistSelectedDevice(selection);
        updateRouteSummary();
    }

    /** HTTP API 改写连接配置后同步回填 Mode 行；不重新枚举设备，也不触发回写。 */
    public void applyConnectionForApi(@Nullable ZaFridaProjectConfig cfg) {
        applyConnectionUi(cfg);
    }

    /** 没有活动项目时连接状态只存在于界面上，API 只能直接改界面；有活动项目必须改配置。 */
    public void setUnsavedConnectionForApi(@NotNull FridaConnectionMode mode, @NotNull String host, int port) {
        connectionModePanel.setConnection(mode, host, port);
        applyTargetFieldMode(mode == FridaConnectionMode.GADGET);
        updateRouteSummary();
    }

    public @NotNull FridaConnectionPlan getConnectionPlanForApi() {
        return currentUiPlan();
    }

    private @Nullable FridaDevice findConnectedComboDevice(@NotNull String deviceId) {
        int count = deviceCombo.getItemCount();
        for (int index = 0; index < count; index++) {
            FridaDevice candidate = deviceCombo.getItemAt(index);
            if (candidate.isConnected() && deviceId.equals(candidate.getId())) {
                return candidate;
            }
        }
        return null;
    }

    private void removeNotConnectedPlaceholder(@NotNull String deviceId) {
        int count = deviceCombo.getItemCount();
        for (int index = 0; index < count; index++) {
            FridaDevice candidate = deviceCombo.getItemAt(index);
            if (!candidate.isConnected() && deviceId.equals(candidate.getId())) {
                deviceCombo.removeItemAt(index);
                return;
            }
        }
    }

    private void persistSelectedDevice(@Nullable FridaDevice selected) {
        // 未连接占位本身就来自已保存的 id，无需回写。
        if (selected == null || !selected.isConnected()) {
            return;
        }
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        if (active == null) {
            return;
        }
        String deviceId = selected.getId();
        fridaProjectManager.updateProjectConfigAsync(active, config -> config.lastDeviceId = deviceId);
    }

    private void persistConnection(@NotNull FridaConnectionMode mode, @NotNull String host, int port) {
        applyTargetFieldMode(mode == FridaConnectionMode.GADGET);
        updateRouteSummary();
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        if (active == null) {
            return;
        }
        fridaProjectManager.updateProjectConfigAsync(active, config -> {
            config.connectionMode = mode;
            config.remoteHost = host;
            config.remotePort = port;
        });
    }

    /** 只在端点真正用于 Run/Attach 时记入全局候选，避免把输到一半的地址存成候选。 */
    private void rememberEndpointPreset(@NotNull FridaConnectionPlan plan) {
        FridaDevice fridaDevice = plan.getFridaDevice();
        if (plan.getMode() == FridaConnectionMode.USB || fridaDevice == null || fridaDevice.getHost() == null) {
            return;
        }
        String endpoint = fridaDevice.getHost();
        ZaFridaSettingsService settingsService =
                ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
        if (endpoint.equals(defaultEndpoint()) || settingsService.getRemoteHosts().contains(endpoint)) {
            return;
        }
        settingsService.addRemoteHost(endpoint);
        connectionModePanel.setEndpointPresets(buildEndpointPresets());
    }

    private @NotNull List<String> buildEndpointPresets() {
        ZaFridaSettingsService settingsService =
                ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
        LinkedHashSet<String> presets = new LinkedHashSet<>();
        presets.add(defaultEndpoint());
        for (String host : settingsService.getRemoteHosts()) {
            if (ZaStrUtil.isNotBlank(host)) {
                presets.add(host.trim());
            }
        }
        return new ArrayList<>(presets);
    }

    private static @NotNull String defaultEndpoint() {
        return ZaFridaNetUtil.formatHostPort(
                ZaFridaConnectionResolver.defaultHost(),
                ZaFridaConnectionResolver.defaultPort()
        );
    }

    public @NotNull String getTargetTextForApi() {
        String text = targetField.getText();
        if (text == null) {
            return "";
        }
        return text.trim();
    }

    public void setTargetTextForApi(@Nullable String target) {
        String normalized;
        if (target == null) {
            normalized = "";
        } else {
            normalized = target.trim();
        }
        targetField.setText(normalized);
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        if (active == null) {
            return;
        }
        fridaProjectManager.updateProjectConfigAsync(active, cfg -> {
            if (normalized.isEmpty()) {
                cfg.lastTarget = null;
            } else {
                cfg.lastTarget = normalized;
            }
        });
    }

    public @NotNull String getExtraArgsForApi() {
        String text = extraArgsField.getText();
        if (text == null) {
            return "";
        }
        return text;
    }

    public void setExtraArgsForApi(@Nullable String args) {
        String normalized;
        if (args == null) {
            normalized = "";
        } else {
            normalized = args;
        }
        extraArgsField.setText(normalized);
    }

    public @NotNull String getRunScriptPathForApi() {
        String text = runScriptField.getText();
        if (text == null) {
            return "";
        }
        return text.trim();
    }

    public @NotNull String getAttachScriptPathForApi() {
        String text = attachScriptField.getText();
        if (text == null) {
            return "";
        }
        return text.trim();
    }

    public void setRunScriptFileForApi(@NotNull VirtualFile file) {
        setRunScriptFile(file);
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        if (active != null) {
            fridaProjectManager.updateMainScriptPathAsync(active, file);
        }
    }

    public void setAttachScriptFileForApi(@NotNull VirtualFile file) {
        setAttachScriptFile(file);
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        if (active != null) {
            fridaProjectManager.updateAttachScriptPathAsync(active, file);
        }
    }

    public @NotNull ZaFridaConsolePanel getRunConsolePanelForApi() {
        return runConsolePanel;
    }

    public @NotNull ZaFridaConsolePanel getAttachConsolePanelForApi() {
        return attachConsolePanel;
    }

    private JPanel buildDeviceRow() {
        deviceCombo.setPrototypeDisplayValue(new FridaDevice(FridaDevice.TYPE_USB, FridaDevice.TYPE_USB, "Android"));
        Dimension minimumSize = deviceCombo.getMinimumSize();
        deviceCombo.setMinimumSize(new Dimension(JBUI.scale(120), minimumSize.height));
        return buildFlexibleRow(deviceCombo, buildInlineActions(refreshDevicesBtn));
    }

    private JPanel buildRunScriptRow() {
        return buildFlexibleRow(runScriptField, buildInlineActions(locateRunScriptBtn, chooseRunScriptBtn));
    }

    private JPanel buildAttachScriptRow() {
        return buildFlexibleRow(attachScriptField, buildInlineActions(locateAttachScriptBtn, chooseAttachScriptBtn));
    }

    private JPanel buildTargetRow() {
        return buildFlexibleRow(targetField, buildInlineActions(forceStopBtn, openAppBtn));
    }

    private JPanel buildExtraRow() {
        JPanel row = new JPanel(new BorderLayout());
        row.add(extraArgsField, BorderLayout.CENTER);
        return row;
    }

    private JPanel buildAdvancedRow() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        row.add(advancedLink);
        return row;
    }

    private void setAdvancedExpanded(boolean expanded, boolean persist) {
        advancedExpanded = expanded;
        extraArgsLabel.setVisible(expanded);
        extraArgsRow.setVisible(expanded);
        updateAdvancedLinkText();
        if (persist) {
            PropertiesComponent.getInstance(project).setValue(ADVANCED_EXPANDED_KEY, expanded, false);
        }
        revalidate();
        repaint();
    }

    private void updateAdvancedLinkText() {
        if (advancedExpanded) {
            advancedLink.setText("Advanced ▾");
            return;
        }
        if (ZaStrUtil.isNotBlank(extraArgsField.getText())) {
            advancedLink.setText("Advanced ▸ · Extra args set");
            return;
        }
        advancedLink.setText("Advanced ▸");
    }

    private JPanel buildButtonsRow() {
        JPanel p = new JPanel(new GridLayout(2, 2, JBUI.scale(8), JBUI.scale(6)));
        p.add(runBtn);
        p.add(stopBtn);
        p.add(attachBtn);
        p.add(stopAttachBtn);
        return p;
    }

    private JPanel buildFlexibleRow(@NotNull JComponent mainComponent,
                                    @NotNull JComponent trailingComponent) {
        JPanel row = new JPanel(new BorderLayout());
        row.add(mainComponent, BorderLayout.CENTER);
        row.add(trailingComponent, BorderLayout.EAST);
        return row;
    }

    private JPanel buildInlineActions(@NotNull JButton... buttons) {
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, JBUI.scale(4), 0));
        actions.setBorder(JBUI.Borders.emptyLeft(4));
        for (JButton button : buttons) {
            button.setMargin(JBUI.insets(2, 4));
            actions.add(button);
        }
        return actions;
    }

    private int addRow(JPanel form, int row, JLabel label, JPanel right) {
        GridBagConstraints c1 = new GridBagConstraints();
        c1.gridx = 0;
        c1.gridy = row;
        c1.insets = new Insets(6, 8, 6, 8);
        c1.anchor = GridBagConstraints.WEST;
        form.add(label, c1);

        GridBagConstraints c2 = new GridBagConstraints();
        c2.gridx = 1;
        c2.gridy = row;
        c2.weightx = 1;
        c2.fill = GridBagConstraints.HORIZONTAL;
        c2.insets = new Insets(6, 8, 6, 8);
        form.add(right, c2);
        return row + 1;
    }

    private int addHintRow(JPanel form, int row, JComponent hint) {
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.gridx = 1;
        constraints.gridy = row;
        constraints.weightx = 1;
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.insets = new Insets(0, 8, 4, 8);
        form.add(hint, constraints);
        return row + 1;
    }

    private void setRunScriptFile(@NotNull VirtualFile file) {
        this.runScriptFile = file;
        setScriptPathText(runScriptField, file.getPath());
        this.templatePanel.setCurrentScriptFile(file);
    }

    private void setAttachScriptFile(@NotNull VirtualFile file) {
        this.attachScriptFile = file;
        setScriptPathText(attachScriptField, file.getPath());
    }

    private void setScriptPathText(@NotNull JBTextField field, @NotNull String path) {
        field.setText(path);
        field.setCaretPosition(field.getDocument().getLength());
        if (path.isEmpty()) {
            field.setToolTipText(null);
        } else {
            field.setToolTipText(path);
        }
    }

    private void locateRunScriptInProjectView() {
        String path = runScriptField.getText();
        VirtualFile file = resolveRunScriptFileForLocate();
        if (file == null || !file.isValid() || file.isDirectory()) {
            if (ZaStrUtil.isBlank(path)) {
                ZaFridaNotifier.warn(project, "ZAFrida", "No script file selected");
            } else {
                ZaFridaNotifier.warn(project, "ZAFrida", String.format("Script file not found: %s", path.trim()));
            }
            return;
        }
        ProjectFileUtil.openAndSelectInProject(project, file);
    }

    private void locateAttachScriptInProjectView() {
        String path = attachScriptField.getText();
        VirtualFile file = resolveAttachScriptFileForLocate();
        if (file == null || !file.isValid() || file.isDirectory()) {
            if (ZaStrUtil.isBlank(path)) {
                ZaFridaNotifier.warn(project, "ZAFrida", "No attach script file selected");
            } else {
                ZaFridaNotifier.warn(project, "ZAFrida", String.format("Attach script file not found: %s", path.trim()));
            }
            return;
        }
        ProjectFileUtil.openAndSelectInProject(project, file);
    }

    private @Nullable VirtualFile resolveRunScriptFileForLocate() {
        if (runScriptFile != null && runScriptFile.isValid()) {
            return runScriptFile;
        }
        VirtualFile templateFile = templatePanel.getCurrentScriptFile();
        if (templateFile != null && templateFile.isValid()) {
            return templateFile;
        }
        String path = runScriptField.getText();
        if (ZaStrUtil.isBlank(path)) {
            return null;
        }
        return LocalFileSystem.getInstance().findFileByPath(path.trim());
    }

    private @Nullable VirtualFile resolveAttachScriptFileForLocate() {
        if (attachScriptFile != null && attachScriptFile.isValid()) {
            return attachScriptFile;
        }
        String path = attachScriptField.getText();
        if (ZaStrUtil.isBlank(path)) {
            return null;
        }
        return LocalFileSystem.getInstance().findFileByPath(path.trim());
    }


    private synchronized void printToolchainInfoIfChanged(int generation) {
        PythonEnvInfo env;
        try {
            env = ProjectPythonEnvResolver.resolve(project);
        } catch (PythonEnvResolutionException e) {
            updateFridaVersionLabelAsync(generation, "—", e.getMessage());
            String errorKey = String.format("error:%s", e.getMessage());
            if (!errorKey.equals(lastPrintedPythonEnvironment)) {
                lastPrintedPythonEnvironment = errorKey;
                runConsolePanel.error(String.format("[ZAFrida] Python environment error: %s", e.getMessage()));
            }
            return;
        }
        if (env == null) {
            updateFridaVersionLabelAsync(generation, "—", "Python environment could not be resolved");
            if (!"none".equals(lastPrintedPythonEnvironment)) {
                lastPrintedPythonEnvironment = "none";
                runConsolePanel.warn("[ZAFrida] Python environment not detected. Using IDE/system PATH for frida-tools.");
            }
            return;
        }

        String environmentKey = String.format("%s:%s", env.getSource().name(), env.getPythonHome());
        String cachedVersion = fridaCli.getDetectedProjectVersion(project);
        if (environmentKey.equals(lastPrintedPythonEnvironment)
                && ZaStrUtil.isNotBlank(cachedVersion)) {
            updateFridaVersionLabelAsync(
                    generation,
                    cachedVersion,
                    String.format("Frida %s in %s", cachedVersion, env.getEnvRoot())
            );
            return;
        }
        String source = "PyCharm project interpreter";
        if (env.getSource() == PythonEnvInfo.Source.ZAFRIDA_PROJECT) {
            source = "ZAFrida project override";
        }
        runConsolePanel.info(String.format("[ZAFrida] Python (%s): %s", source, env.getPythonHome()));
        if (!env.getPathEntries().isEmpty()) {
            runConsolePanel.info(String.format("[ZAFrida] Project PATH prepend: %s", String.join(File.pathSeparator, env.getPathEntries())));
        }

        ZaFridaSettingsState st = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class).getState();
        String ls = ProjectPythonEnvResolver.findTool(env, st.fridaLsDevicesExecutable);
        String ps = ProjectPythonEnvResolver.findTool(env, st.fridaPsExecutable);
        String frida = ProjectPythonEnvResolver.findTool(env, st.fridaExecutable);

        if (ls != null) {
            runConsolePanel.info(String.format("[ZAFrida] Resolved frida-ls-devices: %s", ls));
        } else {
            runConsolePanel.error("[ZAFrida] frida-ls-devices not found in the selected Python environment.");
        }
        if (ps != null) {
            runConsolePanel.info(String.format("[ZAFrida] Resolved frida-ps: %s", ps));
        }
        if (frida != null) {
            runConsolePanel.info(String.format("[ZAFrida] Resolved frida: %s", frida));
        }
        try {
            String version = fridaCli.detectProjectFridaVersion(project);
            runConsolePanel.info(String.format("[ZAFrida] Frida version: %s", version));
            updateFridaVersionLabelAsync(
                    generation,
                    version,
                    String.format("Frida %s in %s", version, env.getEnvRoot())
            );
            lastPrintedPythonEnvironment = environmentKey;
        } catch (RuntimeException e) {
            updateFridaVersionLabelAsync(generation, "—", e.getMessage());
            runConsolePanel.warn(String.format("[ZAFrida] Frida version detection failed: %s", e.getMessage()));
        }
    }

    private void updateFridaVersionLabelAsync(int generation,
                                              @NotNull String text,
                                              @Nullable String tooltip) {
        ApplicationManager.getApplication().invokeLater(() -> {
            if (disposed || project.isDisposed() || generation != deviceReloadGeneration) {
                return;
            }
            setFridaVersionLabel(text, tooltip);
        });
    }

    private void setFridaVersionLabel(@NotNull String text, @Nullable String tooltip) {
        fridaVersionLabel.setText(text);
        fridaVersionLabel.setToolTipText(tooltip);
    }

    private void reloadDevicesAsync() {
        reloadDevicesAsync(null);
    }

    private void reloadDevicesAsync(@Nullable Runnable afterReload) {
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        if (active == null) {
            reloadDevicesAsyncWithConfig(null, afterReload);
            return;
        }
        fridaProjectManager.loadProjectConfigAsync(active, cfg -> reloadDevicesAsyncWithConfig(cfg, afterReload));
    }

    private void reloadDevicesAsyncWithConfig(@Nullable ZaFridaProjectConfig cfg) {
        reloadDevicesAsyncWithConfig(cfg, null);
    }

    /**
     * @param afterReload 枚举结束（无论成败）后在 EDT 执行；本次枚举被更新的一次取代时不会执行。
     */
    private void reloadDevicesAsyncWithConfig(@Nullable ZaFridaProjectConfig cfg, @Nullable Runnable afterReload) {
        int generation = ++deviceReloadGeneration;
        setDevicesLoading(true);
        runConsolePanel.info("[ZAFrida] Loading devices...");

        String savedDeviceId = null;
        if (cfg != null) {
            savedDeviceId = cfg.lastDeviceId;
        }
        final String finalSavedDeviceId = savedDeviceId;
        final int selectionsAtStart = explicitDeviceSelections;
        final boolean usesAdb = ZaFridaConnectionResolver.usesAdb(fridaProjectManager.getActiveProject());

        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                printToolchainInfoIfChanged(generation);
                // Frida 依赖本机 adb server 枚举 Android 设备，但不会自己拉起它。
                AdbService.ServerStartResult adbServer = AdbService.ServerStartResult.skipped();
                if (usesAdb) {
                    adbServer = adbService.ensureServerStarted();
                }
                final AdbService.ServerStartResult finalAdbServer = adbServer;
                List<FridaDevice> devices = sortUsbDevicesFirst(new ArrayList<>(fridaCli.listDevices(project)));

                ApplicationManager.getApplication().invokeLater(() -> {
                    if (disposed || generation != deviceReloadGeneration || project.isDisposed()) {
                        return;
                    }
                    reportAdbServerStart(finalAdbServer);
                    String deviceIdToRestore = finalSavedDeviceId;
                    FridaDevice current = (FridaDevice) deviceCombo.getSelectedItem();
                    if (explicitDeviceSelections != selectionsAtStart && current != null) {
                        // 枚举期间 API 明确选了设备并已写回配置，不能被枚举开始前读到的旧值覆盖。
                        deviceIdToRestore = current.getId();
                    }
                    applyDeviceList(devices, deviceIdToRestore);
                    runConsolePanel.info(String.format("[ZAFrida] Devices loaded: %s", devices.size()));
                    warnIfNoUsbDevices(devices, finalAdbServer);
                    setDevicesLoading(false);
                    if (afterReload != null) {
                        afterReload.run();
                    }
                });
            } catch (Throwable t) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    if (disposed || generation != deviceReloadGeneration || project.isDisposed()) {
                        return;
                    }
                    runConsolePanel.error(String.format("[ZAFrida] Load devices failed: %s", t.getMessage()));
                    setDevicesLoading(false);
                    if (afterReload != null) {
                        afterReload.run();
                    }
                });
            }
        });
    }

    private void reportAdbServerStart(@NotNull AdbService.ServerStartResult adbServer) {
        if (adbServer.getStatus() == AdbService.ServerStartStatus.STARTED) {
            runConsolePanel.info("[ZAFrida] ADB server was not running; started it automatically.");
            return;
        }
        if (adbServer.getStatus() == AdbService.ServerStartStatus.FAILED) {
            runConsolePanel.warn(String.format("[ZAFrida] Could not start ADB server: %s", adbServer.getDetail()));
        }
    }

    private void applyDeviceList(@NotNull List<FridaDevice> devices, @Nullable String savedDeviceId) {
        FridaDevice selection = chooseDeviceSelection(devices, savedDeviceId);
        updatingDeviceCombo = true;
        try {
            deviceCombo.removeAllItems();
            for (FridaDevice device : devices) {
                deviceCombo.addItem(device);
            }
            if (selection != null && !selection.isConnected()) {
                deviceCombo.addItem(selection);
            }
            deviceCombo.setSelectedItem(selection);
        } finally {
            updatingDeviceCombo = false;
        }
        if (selection != null && !selection.isConnected()) {
            notifyMissingDeviceIfBlocking(selection.getId());
        }
    }

    /**
     * 恢复选中的规则：保存的设备在线就选它；不在线且恰好只有一台 USB 设备时临时改用那一台
     * （不写回配置，原设备重新接入后仍恢复为它）；其余情况返回未连接占位并由执行入口拦截。
     * 有保存值时绝不静默换成列表第一台，否则 adb 会操作到另一台手机。
     */
    private @Nullable FridaDevice chooseDeviceSelection(@NotNull List<FridaDevice> devices,
                                                        @Nullable String savedDeviceId) {
        if (ZaStrUtil.isBlank(savedDeviceId) || FridaDevice.GENERIC_USB_ID.equalsIgnoreCase(savedDeviceId.trim())) {
            lastMissingDeviceId = null;
            announcedDeviceSubstitution = null;
            if (devices.isEmpty()) {
                return null;
            }
            return devices.get(0);
        }

        String savedId = savedDeviceId.trim();
        FridaDevice saved = findDeviceById(devices, savedId);
        if (saved != null) {
            lastMissingDeviceId = null;
            announcedDeviceSubstitution = null;
            notifiedMissingDeviceIds.remove(savedId);
            return saved;
        }

        FridaDevice onlyUsbDevice = findOnlyUsbDevice(devices);
        if (onlyUsbDevice != null) {
            announceDeviceSubstitution(savedId, onlyUsbDevice);
            return onlyUsbDevice;
        }

        logMissingDevice(savedId);
        return FridaDevice.notConnected(savedId);
    }

    private void announceDeviceSubstitution(@NotNull String savedId, @NotNull FridaDevice substitute) {
        lastMissingDeviceId = null;
        String key = String.format("%s>%s", savedId, substitute.getId());
        if (key.equals(announcedDeviceSubstitution)) {
            return;
        }
        announcedDeviceSubstitution = key;
        runConsolePanel.warn(String.format(
                "[ZAFrida] Saved device %s is not connected; using the only USB device %s (%s) for now.",
                savedId, substitute.getName(), substitute.getId()));
    }

    private void logMissingDevice(@NotNull String savedId) {
        announcedDeviceSubstitution = null;
        if (savedId.equals(lastMissingDeviceId)) {
            return;
        }
        lastMissingDeviceId = savedId;
        runConsolePanel.warn(String.format(
                "[ZAFrida] Saved device %s is not connected. Connect it or select another device.", savedId));
    }

    /**
     * 只有缺失的设备确实挡住当前路由时才弹通知；纯 Remote 或 iOS 项目里设备不参与连接，只在 Console 提示。
     * 每个设备 id 只弹一次，直到它重新上线，避免在几个项目之间切换时反复弹出。
     */
    private void notifyMissingDeviceIfBlocking(@NotNull String savedId) {
        if (currentUiPlan().getSessionBlocker() == null || !notifiedMissingDeviceIds.add(savedId)) {
            return;
        }
        ZaFridaNotifier.warn(project, "ZAFrida", String.format(
                "Saved device %s is not connected. Connect it or select another device.", savedId));
    }

    private void applyConnectionUi(@Nullable ZaFridaProjectConfig cfg) {
        FridaConnectionMode mode = ZaFridaConnectionResolver.resolveMode(cfg);
        connectionModePanel.setConnection(
                mode,
                ZaFridaConnectionResolver.resolveHost(cfg),
                ZaFridaConnectionResolver.resolvePort(cfg)
        );
        connectionModePanel.setEndpointPresets(buildEndpointPresets());
        applyTargetFieldMode(mode == FridaConnectionMode.GADGET);
        updateRouteSummary();
    }

    private void applyTargetFieldMode(boolean gadgetMode) {
        // Gadget 模式不读取 Target，但包名仍要能选中复制，所以用只读而不是禁用。
        targetField.setEditable(!gadgetMode);
        if (gadgetMode) {
            targetField.setToolTipText(GADGET_TARGET_TOOLTIP);
        } else {
            targetField.setToolTipText(TARGET_TOOLTIP);
        }
    }

    /** 由界面当前状态得到的连接方案；Mode 行与项目配置保持同步，设备以下拉框选中项为准。 */
    private @NotNull FridaConnectionPlan currentUiPlan() {
        return FridaConnectionPlan.resolve(
                connectionModePanel.getMode(),
                connectionModePanel.getHost(),
                connectionModePanel.getPort(),
                (FridaDevice) deviceCombo.getSelectedItem(),
                ZaFridaConnectionResolver.usesAdb(fridaProjectManager.getActiveProject())
        );
    }

    private void updateRouteSummary() {
        if (devicesLoading) {
            routeSummaryLabel.setText(DEVICES_LOADING_SUMMARY);
            routeSummaryLabel.setToolTipText(null);
            routeSummaryLabel.setForeground(UIUtil.getContextHelpForeground());
            return;
        }
        FridaConnectionPlan plan = currentUiPlan();
        String summary = plan.getSummary();
        routeSummaryLabel.setText(summary);
        routeSummaryLabel.setToolTipText(summary);
        if (plan.getSessionBlocker() != null) {
            routeSummaryLabel.setForeground(JBColor.RED);
        } else {
            routeSummaryLabel.setForeground(UIUtil.getContextHelpForeground());
        }
    }

    private static @Nullable FridaDevice findDeviceById(@NotNull List<FridaDevice> devices, @NotNull String id) {
        for (FridaDevice d : devices) {
            if (id.equals(d.getId())) {
                return d;
            }
        }
        return null;
    }

    private static @NotNull List<FridaDevice> sortUsbDevicesFirst(@NotNull List<FridaDevice> devices) {
        if (devices.isEmpty()) {
            return devices;
        }
        List<FridaDevice> usbDevices = new ArrayList<>();
        List<FridaDevice> others = new ArrayList<>();
        for (FridaDevice device : devices) {
            if (device.isUsb()) {
                usbDevices.add(device);
            } else {
                others.add(device);
            }
        }
        if (usbDevices.isEmpty() || others.isEmpty()) {
            return devices;
        }
        List<FridaDevice> sorted = new ArrayList<>(devices.size());
        sorted.addAll(usbDevices);
        sorted.addAll(others);
        return sorted;
    }

    private void warnIfNoUsbDevices(@NotNull List<FridaDevice> devices,
                                    @NotNull AdbService.ServerStartResult adbServer) {
        if (findFirstUsbDevice(devices) != null) {
            warnedNoUsbDevices = false;
            return;
        }
        if (warnedNoUsbDevices) {
            return;
        }
        warnedNoUsbDevices = true;
        if (adbServer.getStatus() == AdbService.ServerStartStatus.UNAVAILABLE) {
            runConsolePanel.warn("[ZAFrida] No USB devices found. adb is not available, so the ADB server could not be started automatically; Android devices need adb in PATH.");
            return;
        }
        runConsolePanel.warn("[ZAFrida] No USB devices found. Check the USB cable and that the device trusts this computer (Android: USB debugging authorization).");
    }

    private static @Nullable FridaDevice findFirstUsbDevice(@NotNull List<FridaDevice> devices) {
        for (FridaDevice device : devices) {
            if (device.isUsb()) {
                return device;
            }
        }
        return null;
    }

    /** 恰好只有一台 USB 设备时返回它，0 台或多台返回 null。 */
    private static @Nullable FridaDevice findOnlyUsbDevice(@NotNull List<FridaDevice> devices) {
        FridaDevice only = null;
        for (FridaDevice device : devices) {
            if (!device.isUsb()) {
                continue;
            }
            if (only != null) {
                return null;
            }
            only = device;
        }
        return only;
    }


    private void runFrida() {
        withFreshDeviceSelection(this::runFridaWithCurrentInputs);
    }

    private void attachFrida() {
        withFreshDeviceSelection(this::attachFridaWithCurrentInputs);
    }

    /**
     * 选中的是未连接占位时先重新枚举一次再继续：用户很可能刚插上手机还没点刷新。
     * 重新枚举后仍不在线，则由后续的连接方案拦截并提示。
     */
    private void withFreshDeviceSelection(@NotNull Runnable action) {
        FridaDevice selected = (FridaDevice) deviceCombo.getSelectedItem();
        if (selected == null || selected.isConnected() || devicesLoading) {
            action.run();
            return;
        }
        reloadDevicesAsync(action);
    }

    private void runFridaWithCurrentInputs() {
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        String targetText = targetField.getText();
        String target;
        if (targetText == null) {
            target = "";
        } else {
            target = targetText.trim();
        }
        String extraArgsText = extraArgsField.getText();
        String extraArgs;
        if (extraArgsText == null) {
            extraArgs = "";
        } else {
            extraArgs = extraArgsText;
        }
        VirtualFile preferredScript = runScriptFile;
        if (preferredScript == null) {
            preferredScript = templatePanel.getCurrentScriptFile();
        }
        final VirtualFile finalPreferredScript = preferredScript;

        if (active == null) {
            runFridaWithConfig(null, null, target, extraArgs, finalPreferredScript);
            return;
        }
        fridaProjectManager.loadProjectConfigAsync(active, cfg ->
                runFridaWithConfig(active, cfg, target, extraArgs, finalPreferredScript));
    }

    private void attachFridaWithCurrentInputs() {
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        String targetText = targetField.getText();
        String target;
        if (targetText == null) {
            target = "";
        } else {
            target = targetText.trim();
        }
        String extraArgsText = extraArgsField.getText();
        String extraArgs;
        if (extraArgsText == null) {
            extraArgs = "";
        } else {
            extraArgs = extraArgsText;
        }
        VirtualFile preferredScript = attachScriptFile;
        final VirtualFile finalPreferredScript = preferredScript;

        if (active == null) {
            attachFridaWithConfig(null, null, target, extraArgs, finalPreferredScript);
            return;
        }
        fridaProjectManager.loadProjectConfigAsync(active, cfg ->
                attachFridaWithConfig(active, cfg, target, extraArgs, finalPreferredScript));
    }

    private void runFridaWithConfig(@Nullable ZaFridaFridaProject active,
                                    @Nullable ZaFridaProjectConfig projectConfig,
                                    @NotNull String target,
                                    @NotNull String extraArgs,
                                    @Nullable VirtualFile preferredScript) {
        FridaConnectionPlan plan = resolveSessionPlan(active, projectConfig, runConsolePanel);
        if (plan == null) {
            return;
        }
        final boolean gadgetMode = plan.isGadget();

        if (!gadgetMode && target.isEmpty()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Target is empty");
            return;
        }

        resolveRunScriptAsync(active, target, gadgetMode, preferredScript, script -> {
            if (script == null) {
                ZaFridaNotifier.warn(project, "ZAFrida", "Choose a run script file first");
                return;
            }

            if (active != null && !gadgetMode) {
                fridaProjectManager.updateProjectConfigAsync(active, c -> c.lastTarget = target);
            }
            if (active != null) {
                fridaProjectManager.updateMainScriptPathAsync(active, script);
            }

            FridaRunMode mode = new SpawnRunMode(target);
            if (gadgetMode) {
                mode = new FrontmostRunMode();
            }
            launchSession(ZaFridaSessionType.RUN, plan, mode, script, extraArgs, target);
        });
    }

    private void attachFridaWithConfig(@Nullable ZaFridaFridaProject active,
                                       @Nullable ZaFridaProjectConfig projectConfig,
                                       @NotNull String target,
                                       @NotNull String extraArgs,
                                       @Nullable VirtualFile preferredScript) {
        FridaConnectionPlan plan = resolveSessionPlan(active, projectConfig, attachConsolePanel);
        if (plan == null) {
            return;
        }
        final boolean gadgetMode = plan.isGadget();

        if (!gadgetMode && target.isEmpty()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Target is empty");
            return;
        }

        resolveAttachScriptAsync(active, preferredScript, script -> {
            if (script == null) {
                ZaFridaNotifier.warn(project, "ZAFrida", "Choose an attach script file first");
                return;
            }

            if (active != null) {
                fridaProjectManager.updateAttachScriptPathAsync(active, script);
            }
            if (active != null && !gadgetMode) {
                fridaProjectManager.updateProjectConfigAsync(active, c -> c.lastTarget = target);
            }

            FridaRunMode mode;
            try {
                mode = createAttachRunMode(target, gadgetMode);
            } catch (IllegalArgumentException e) {
                attachConsolePanel.error(String.format("[ZAFrida] %s", e.getMessage()));
                ZaFridaNotifier.warn(project, "ZAFrida", e.getMessage());
                return;
            }
            launchSession(ZaFridaSessionType.ATTACH, plan, mode, script, extraArgs, target);
        });
    }

    /**
     * 有活动项目时以项目配置为准（API 可能刚改写过配置，界面回填是异步的）；
     * 自由脚本模式没有配置，连接状态只存在于界面上。设备始终取界面当前选中项。
     */
    private @NotNull FridaConnectionPlan resolvePlan(@Nullable ZaFridaFridaProject active,
                                                     @Nullable ZaFridaProjectConfig projectConfig) {
        if (active == null) {
            return currentUiPlan();
        }
        FridaDevice selected = (FridaDevice) deviceCombo.getSelectedItem();
        return ZaFridaConnectionResolver.resolve(active, projectConfig, selected);
    }

    /** 被设备状态拦截时已提示用户并返回 null。 */
    private @Nullable FridaConnectionPlan resolveSessionPlan(@Nullable ZaFridaFridaProject active,
                                                             @Nullable ZaFridaProjectConfig projectConfig,
                                                             @NotNull ZaFridaConsolePanel console) {
        FridaConnectionPlan plan = resolvePlan(active, projectConfig);
        String blocker = plan.getSessionBlocker();
        if (blocker != null) {
            console.warn(String.format("[ZAFrida] %s", blocker));
            ZaFridaNotifier.warn(project, "ZAFrida", blocker);
            return null;
        }
        return plan;
    }

    private void launchSession(@NotNull ZaFridaSessionType type,
                               @NotNull FridaConnectionPlan plan,
                               @NotNull FridaRunMode mode,
                               @NotNull VirtualFile script,
                               @NotNull String extraArgs,
                               @NotNull String target) {
        ZaFridaConsolePanel console = resolveConsoleForSessionType(type);
        FridaDevice fridaDevice = plan.getFridaDevice();
        if (fridaDevice == null) {
            console.error("[ZAFrida] No Frida device resolved for this session.");
            return;
        }
        FridaRunConfig cfg = new FridaRunConfig(fridaDevice, mode, script.getPath(), extraArgs);
        rememberEndpointPreset(plan);

        String fridaProjectDir = null;
        if (activeProjectDir != null && activeProjectDir.isValid()) {
            fridaProjectDir = activeProjectDir.getPath();
        }
        String targetPackage = null;
        if (!plan.isGadget() && !target.isEmpty()) {
            targetPackage = target;
        }

        if (type == ZaFridaSessionType.ATTACH) {
            consoleTabsPanel.showAttachConsole();
        } else {
            consoleTabsPanel.showRunConsole();
        }
        warnIfTypeScriptNeedsFrida17(script, console);

        String finalFridaProjectDir = fridaProjectDir;
        String finalTargetPackage = targetPackage;
        Runnable startSession = () ->
                startFridaSession(type, cfg, console, finalFridaProjectDir, finalTargetPackage);
        if (!plan.isAdbForwardRequired()) {
            startSession.run();
            return;
        }

        int forwardPort = plan.getForwardPort();
        adbService.forwardTcp(forwardPort, plan.getAdbSerial(), console::info, console::warn, success -> {
            // 转发失败只提醒不中止：用户可能自建了隧道，或该端口上已有可用的转发。
            if (!success) {
                ZaFridaNotifier.warn(project, "ZAFrida", String.format(
                        "ADB forward tcp:%s failed. Starting Frida anyway; see the console for details.",
                        forwardPort));
            }
            startSession.run();
        });
    }

    private void resolveRunScriptAsync(@Nullable ZaFridaFridaProject active,
                                       @NotNull String target,
                                       boolean gadgetMode,
                                       @Nullable VirtualFile preferredScript,
                                       @NotNull Consumer<VirtualFile> uiConsumer) {
        if (preferredScript != null && preferredScript.isValid() && !preferredScript.isDirectory()) {
            uiConsumer.accept(preferredScript);
            return;
        }
        if (active == null) {
            uiConsumer.accept(null);
            return;
        }
        fridaProjectManager.resolveRunScriptFileAsync(active, target, gadgetMode, script -> {
            if (script != null && !script.isDirectory()) {
                setRunScriptFile(script);
            }
            uiConsumer.accept(script);
        });
    }

    private void resolveAttachScriptAsync(@Nullable ZaFridaFridaProject active,
                                          @Nullable VirtualFile preferredScript,
                                          @NotNull Consumer<VirtualFile> uiConsumer) {
        if (preferredScript != null && preferredScript.isValid() && !preferredScript.isDirectory()) {
            uiConsumer.accept(preferredScript);
            return;
        }
        if (active == null) {
            uiConsumer.accept(null);
            return;
        }
        fridaProjectManager.resolveAttachScriptFileAsync(active, script -> {
            if (script != null && !script.isDirectory()) {
                setAttachScriptFile(script);
            }
            uiConsumer.accept(script);
        });
    }

    private @Nullable FridaDevice getSelectedDeviceForDiagnostics() {
        return currentUiPlan().getFridaDevice();
    }

    private void startFridaSession(@NotNull ZaFridaSessionType type,
                                   @NotNull FridaRunConfig cfg,
                                   @NotNull ZaFridaConsolePanel console,
                                   @Nullable String fridaProjectDir,
                                   @Nullable String targetPackage) {
        if (disposed || project.isDisposed()) {
            return;
        }
        try {
            RunningSession session = sessionService.start(
                    type,
                    cfg,
                    console.getConsoleView(),
                    console::info,
                    console::error,
                    fridaProjectDir,
                    targetPackage
            );

            session.getProcessHandler().addProcessListener(sessionService.createUiStateListener(() -> {
                if (!disposed) {
                    updateRunningState();
                }
            }));

            updateRunningState();
            console.setLogFilePath(session.getLogFilePath());
            console.info(String.format("[ZAFrida] Log file: %s", session.getLogFilePath()));
        } catch (Throwable t) {
            console.error(String.format("[ZAFrida] Start failed: %s", t.getMessage()));
            ZaFridaNotifier.error(project, "ZAFrida", String.format("Start failed: %s", t.getMessage()));
        }
    }

    private void warnIfTypeScriptNeedsFrida17(@NotNull VirtualFile script,
                                              @NotNull ZaFridaConsolePanel console) {
        if ("ts".equalsIgnoreCase(script.getExtension()) && !fridaCli.isFrida17OrLater(project)) {
            console.warn("[ZAFrida] Direct .ts loading requires Frida 17; use frida-compile output with Frida 16.");
        }
    }

    private void stopRunSession() {
        stopSession(ZaFridaSessionType.RUN);
    }

    private void stopAttachSession() {
        stopSession(ZaFridaSessionType.ATTACH);
    }

    private void stopSession(@NotNull ZaFridaSessionType type) {
        if (stoppingSessions.contains(type)) {
            return;
        }
        stoppingSessions.add(type);
        updateRunningState();
        ZaFridaConsolePanel console = resolveConsoleForSessionType(type);
        console.info("[ZAFrida] Stopping...");
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            sessionService.stop(type);
            ApplicationManager.getApplication().invokeLater(() -> {
                if (disposed || project.isDisposed()) {
                    return;
                }
                stoppingSessions.remove(type);
                updateRunningState();
                console.info("[ZAFrida] Stopped");
            });
        });
    }

    private void forceStopApp() {
        withFreshDeviceSelection(() -> runAdbAppAction("Force stop", (packageName, adbSerial) ->
                adbService.forceStop(packageName, adbSerial, runConsolePanel::info, runConsolePanel::error)));
    }

    private void openApp() {
        withFreshDeviceSelection(() -> runAdbAppAction("Open app", (packageName, adbSerial) ->
                adbService.openApp(packageName, adbSerial, runConsolePanel::info, runConsolePanel::error)));
    }

    /** action 的第二个参数是 adb serial，为空表示不带 {@code -s}。 */
    private void runAdbAppAction(@NotNull String actionName, @NotNull BiConsumer<String, String> action) {
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        String targetText = getTargetTextForApi();
        if (active == null) {
            runAdbAppActionWithConfig(actionName, null, null, targetText, action);
            return;
        }
        fridaProjectManager.loadProjectConfigAsync(active, cfg ->
                runAdbAppActionWithConfig(actionName, active, cfg, targetText, action));
    }

    private void runAdbAppActionWithConfig(@NotNull String actionName,
                                           @Nullable ZaFridaFridaProject active,
                                           @Nullable ZaFridaProjectConfig projectConfig,
                                           @NotNull String targetText,
                                           @NotNull BiConsumer<String, String> action) {
        String packageName = resolveAdbPackage(projectConfig, targetText);
        if (ZaStrUtil.isBlank(packageName)) {
            String message = String.format("%s requires a package name", actionName);
            ZaFridaNotifier.warn(project, "ZAFrida", message);
            runConsolePanel.warn(String.format("[ZAFrida] %s.", message));
            return;
        }

        FridaConnectionPlan plan = resolvePlan(active, projectConfig);
        String blocker = plan.getAdbBlocker();
        if (blocker != null) {
            ZaFridaNotifier.warn(project, "ZAFrida", blocker);
            runConsolePanel.warn(String.format("[ZAFrida] %s", blocker));
            return;
        }
        action.accept(packageName, plan.getAdbSerial());
    }

    /** 以界面上可见的 Target 为准（Gadget 模式下它只读显示项目保存的包名），纯数字 PID 回退到项目配置。 */
    private @Nullable String resolveAdbPackage(@Nullable ZaFridaProjectConfig cfg, @NotNull String targetText) {
        if (!targetText.isEmpty() && !ZaFridaTextUtil.isNumeric(targetText)) {
            return targetText;
        }
        if (cfg != null && ZaStrUtil.isNotBlank(cfg.lastTarget)) {
            return cfg.lastTarget.trim();
        }
        return null;
    }

    private @NotNull FridaRunMode createAttachRunMode(@NotNull String target, boolean gadgetMode) {
        if (gadgetMode) {
            return new FrontmostRunMode();
        }
        if (ZaFridaTextUtil.isNumeric(target)) {
            try {
                return new AttachPidRunMode(Integer.parseInt(target));
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(String.format("Invalid process PID: %s", target), e);
            }
        }
        return new AttachNameRunMode(target);
    }

    private void updateRunningState() {
        boolean runRunning = sessionService.isRunning(ZaFridaSessionType.RUN);
        boolean attachRunning = sessionService.isRunning(ZaFridaSessionType.ATTACH);
        boolean runStopping = stoppingSessions.contains(ZaFridaSessionType.RUN);
        boolean attachStopping = stoppingSessions.contains(ZaFridaSessionType.ATTACH);
        runBtn.setEnabled(!runRunning && !runStopping);
        attachBtn.setEnabled(!attachRunning && !attachStopping);
        stopBtn.setEnabled(runRunning && !runStopping);
        stopAttachBtn.setEnabled(attachRunning && !attachStopping);
        consoleTabsPanel.updateSessionState(ZaFridaSessionType.RUN, runRunning, runStopping);
        consoleTabsPanel.updateSessionState(ZaFridaSessionType.ATTACH, attachRunning, attachStopping);
    }

    private @NotNull ZaFridaConsolePanel resolveConsoleForSessionType(@NotNull ZaFridaSessionType type) {
        if (type == ZaFridaSessionType.ATTACH) {
            return attachConsolePanel;
        }
        return runConsolePanel;
    }

    private void setDevicesLoading(boolean loading) {
        devicesLoading = loading;
        deviceCombo.setEnabled(!loading);
        refreshDevicesBtn.setEnabled(!loading);
        updateRouteSummary();
    }

    private static final class PendingProjectAction {
        private final @NotNull ZaFridaFridaProject expectedProject;
        private final @NotNull Runnable action;

        private PendingProjectAction(@NotNull ZaFridaFridaProject expectedProject, @NotNull Runnable action) {
            this.expectedProject = expectedProject;
            this.action = action;
        }
    }

    @Override
    public void dispose() {
        disposed = true;
        activeProjectUiGeneration++;
        deviceReloadGeneration++;
        localHttpApiService.unbindRunPanel(this);
    }
}
