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
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.vfs.LocalFileSystem;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.ui.components.ActionLink;
import com.intellij.ui.components.JBTextField;
import com.intellij.util.ui.JBUI;
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
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Supplier;

public final class ZaFridaRunPanel extends JPanel implements Disposable {

    private static final Logger LOG = Logger.getInstance(ZaFridaRunPanel.class);
    private static final String USB_DEVICE_TYPE = "usb";
    private static final String ADB_SHELL_COMMAND = "adb shell";
    private static final String ADVANCED_EXPANDED_KEY = "zafrida.session.advanced.expanded";

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
    private final JButton addRemoteBtn = new JButton("");

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
    private @Nullable String lastMissingUsbDeviceId;

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

        targetField.setToolTipText("Spawn/Attach uses package name");

        refreshDevicesBtn.setIcon(AllIcons.Actions.Refresh);
        refreshDevicesBtn.setToolTipText("Refresh devices");
        addRemoteBtn.setIcon(AllIcons.General.Add);
        addRemoteBtn.setToolTipText("Add remote host");
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

        addRemoteBtn.addActionListener(e -> {
            ZaFridaSettingsState st = ApplicationManager.getApplication()
                    .getService(ZaFridaSettingsService.class)
                    .getState();
            String defHost = ZaFridaNetUtil.defaultHost(st.defaultRemoteHost);
            int defPort = ZaFridaNetUtil.defaultPort(st.defaultRemotePort);
            String initial = String.format("%s:%s", defHost, defPort);

            String host = Messages.showInputDialog(this, "host:port", "Add Frida Remote Host", null, initial, null);
            if (host == null) {
                return;
            }
            String h = host.trim();
            if (h.isEmpty()) {
                return;
            }
            ApplicationManager.getApplication().getService(ZaFridaSettingsService.class).addRemoteHost(h);
            reloadDevicesAsync();
        });

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
            persistSelectedDevice(selected);
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
            targetField.setEnabled(true);
            targetField.setToolTipText(null);
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
        int count = deviceCombo.getItemCount();
        for (int i = 0; i < count; i++) {
            FridaDevice item = deviceCombo.getItemAt(i);
            if (normalized.equals(item.getId())) {
                deviceCombo.setSelectedItem(item);
                return true;
            }
        }
        return false;
    }

    public boolean selectDeviceByHostForApi(@NotNull String host) {
        String normalized = host.trim();
        if (normalized.isEmpty()) {
            return false;
        }
        int count = deviceCombo.getItemCount();
        for (int i = 0; i < count; i++) {
            FridaDevice item = deviceCombo.getItemAt(i);
            String itemHost = item.getHost();
            if (itemHost != null && normalized.equals(itemHost)) {
                deviceCombo.setSelectedItem(item);
                return true;
            }
        }
        return false;
    }

    public void selectDeviceForApi(@NotNull FridaDevice device) {
        updatingDeviceCombo = true;
        try {
            FridaDevice existing = null;
            int count = deviceCombo.getItemCount();
            for (int index = 0; index < count; index++) {
                FridaDevice candidate = deviceCombo.getItemAt(index);
                if (device.getMode() == FridaDeviceMode.HOST) {
                    if (Objects.equals(device.getHost(), candidate.getHost())) {
                        existing = candidate;
                        break;
                    }
                } else if (device.getId().equals(candidate.getId())) {
                    existing = candidate;
                    break;
                }
            }
            if (existing == null) {
                deviceCombo.addItem(device);
                existing = device;
            }
            deviceCombo.setSelectedItem(existing);
        } finally {
            updatingDeviceCombo = false;
        }
        persistSelectedDevice(device);
    }

    private void persistSelectedDevice(@Nullable FridaDevice selected) {
        if (selected == null) {
            return;
        }
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        if (active == null) {
            return;
        }
        fridaProjectManager.updateProjectConfigAsync(active, config -> {
            if (selected.getMode() == FridaDeviceMode.HOST) {
                config.lastDeviceHost = selected.getHost();
            } else {
                config.lastDeviceId = selected.getId();
            }
        });
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
        deviceCombo.setPrototypeDisplayValue(new FridaDevice(USB_DEVICE_TYPE, USB_DEVICE_TYPE, "Android"));
        Dimension minimumSize = deviceCombo.getMinimumSize();
        deviceCombo.setMinimumSize(new Dimension(JBUI.scale(120), minimumSize.height));
        return buildFlexibleRow(deviceCombo, buildInlineActions(refreshDevicesBtn, addRemoteBtn));
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
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        if (active == null) {
            reloadDevicesAsyncWithConfig(null);
            return;
        }
        fridaProjectManager.loadProjectConfigAsync(active, this::reloadDevicesAsyncWithConfig);
    }

    private void reloadDevicesAsyncWithConfig(@Nullable ZaFridaProjectConfig cfg) {
        int generation = ++deviceReloadGeneration;
        disableControls(true);
        runConsolePanel.info("[ZAFrida] Loading devices...");

        FridaConnectionMode connectionMode;
        if (cfg != null && cfg.connectionMode != null) {
            connectionMode = cfg.connectionMode;
        } else {
            connectionMode = FridaConnectionMode.USB;
        }
        final FridaConnectionMode finalConnectionMode = connectionMode;

        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                printToolchainInfoIfChanged(generation);
                List<FridaDevice> devices = new ArrayList<>(fridaCli.listDevices(project));
                ZaFridaSettingsService settingsService =
                        ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
                List<String> remotes = settingsService.getRemoteHosts();
                for (String host : remotes) {
                    if (!containsHost(devices, host)) {
                        devices.add(new FridaDevice(String.format("remote:%s", host), "remote", "Remote", FridaDeviceMode.HOST, host));
                    }
                }

                if (cfg != null && (finalConnectionMode == FridaConnectionMode.REMOTE || finalConnectionMode == FridaConnectionMode.GADGET)) {
                    String host = resolveHostPort(cfg);
                    if (!containsHost(devices, host)) {
                        String type;
                        String name;
                        if (finalConnectionMode == FridaConnectionMode.GADGET) {
                            type = "gadget";
                            name = "Gadget";
                        } else {
                            type = "remote";
                            name = "Remote";
                        }
                        devices.add(new FridaDevice(String.format("%s:%s", type, host), type, name, FridaDeviceMode.HOST, host));
                    }
                }
                List<FridaDevice> sortedDevices = sortUsbDevicesFirst(devices);

                ApplicationManager.getApplication().invokeLater(() -> {
                    if (disposed || generation != deviceReloadGeneration || project.isDisposed()) {
                        return;
                    }
                    updatingDeviceCombo = true;
                    try {
                        deviceCombo.removeAllItems();
                        for (FridaDevice d : sortedDevices) {
                            deviceCombo.addItem(d);
                        }
                        selectSavedDevice(sortedDevices, cfg);
                    } finally {
                        updatingDeviceCombo = false;
                    }
                    runConsolePanel.info(String.format("[ZAFrida] Devices loaded: %s", sortedDevices.size()));
                    applyUsbDeviceHints(sortedDevices, cfg, finalConnectionMode);
                    disableControls(false);
                });
            } catch (Throwable t) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    if (disposed || generation != deviceReloadGeneration || project.isDisposed()) {
                        return;
                    }
                    runConsolePanel.error(String.format("[ZAFrida] Load devices failed: %s", t.getMessage()));
                    disableControls(false);
                });
            }
        });
    }

    private void applyConnectionUi(@NotNull ZaFridaProjectConfig cfg) {
        FridaConnectionMode mode = cfg.connectionMode;
        if (mode == null) {
            mode = FridaConnectionMode.USB;
        }
        boolean gadgetMode = mode == FridaConnectionMode.GADGET;
        targetField.setEnabled(!gadgetMode);
        if (gadgetMode) {
            targetField.setToolTipText("Gadget mode uses -F; target is ignored.");
        } else {
            targetField.setToolTipText("Spawn/Attach uses package name");
        }
    }

    private void selectSavedDevice(@NotNull List<FridaDevice> devices, @Nullable ZaFridaProjectConfig cfg) {
        FridaDevice match = null;
        if (cfg != null) {
            if (cfg.connectionMode == FridaConnectionMode.REMOTE || cfg.connectionMode == FridaConnectionMode.GADGET) {
                String host = resolveHostPort(cfg);
                match = findDeviceByHost(devices, host);
            }
            if (match == null) {
                if (ZaStrUtil.isNotBlank(cfg.lastDeviceHost)) {
                    match = findDeviceByHost(devices, cfg.lastDeviceHost);
                } else if (ZaStrUtil.isNotBlank(cfg.lastDeviceId)) {
                    match = findDeviceById(devices, cfg.lastDeviceId);
                }
            }
        }
        if (match != null) {
            deviceCombo.setSelectedItem(match);
            return;
        }
        if (!devices.isEmpty()) {
            deviceCombo.setSelectedIndex(0);
        }
    }

    private static @Nullable FridaDevice findDeviceByHost(@NotNull List<FridaDevice> devices, @NotNull String host) {
        for (FridaDevice d : devices) {
            if (host.equals(d.getHost())) {
                return d;
            }
        }
        return null;
    }

    private static @Nullable FridaDevice findDeviceById(@NotNull List<FridaDevice> devices, @NotNull String id) {
        for (FridaDevice d : devices) {
            if (id.equals(d.getId())) {
                return d;
            }
        }
        return null;
    }

    private static boolean containsHost(@NotNull List<FridaDevice> devices, @NotNull String host) {
        return findDeviceByHost(devices, host) != null;
    }

    private static @NotNull List<FridaDevice> sortUsbDevicesFirst(@NotNull List<FridaDevice> devices) {
        if (devices.isEmpty()) {
            return devices;
        }
        List<FridaDevice> usbDevices = new ArrayList<>();
        List<FridaDevice> others = new ArrayList<>();
        for (FridaDevice device : devices) {
            if (isUsbDevice(device)) {
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

    private void applyUsbDeviceHints(@NotNull List<FridaDevice> devices,
                                     @Nullable ZaFridaProjectConfig cfg,
                                     @NotNull FridaConnectionMode connectionMode) {
        boolean hasUsb = hasUsbDevice(devices);
        if (hasUsb) {
            warnedNoUsbDevices = false;
        } else {
            if (!warnedNoUsbDevices) {
                runConsolePanel.warn(String.format(
                        "[ZAFrida] No USB devices found. If you're using USB mode, run \"%s\" in a terminal to initialize the ADB connection.",
                        ADB_SHELL_COMMAND));
                warnedNoUsbDevices = true;
            }
        }

        if (cfg == null) {
            lastMissingUsbDeviceId = null;
            return;
        }
        if (connectionMode != FridaConnectionMode.USB) {
            lastMissingUsbDeviceId = null;
            return;
        }
        if (ZaStrUtil.isBlank(cfg.lastDeviceId)) {
            lastMissingUsbDeviceId = null;
            return;
        }
        if (findDeviceById(devices, cfg.lastDeviceId) != null) {
            lastMissingUsbDeviceId = null;
            return;
        }
        if (!cfg.lastDeviceId.equals(lastMissingUsbDeviceId)) {
            ZaFridaNotifier.warn(project, "ZAFrida",
                    String.format("Saved USB device not found: %s. Please refresh or switch device.", cfg.lastDeviceId));
            lastMissingUsbDeviceId = cfg.lastDeviceId;
        }
    }

    private static boolean hasUsbDevice(@NotNull List<FridaDevice> devices) {
        for (FridaDevice device : devices) {
            if (isUsbDevice(device)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isUsbDevice(@NotNull FridaDevice device) {
        return USB_DEVICE_TYPE.equalsIgnoreCase(device.getType());
    }

    private @NotNull String resolveHostPort(@Nullable ZaFridaProjectConfig cfg) {
        return String.format("%s:%s", resolveRemoteHost(cfg), resolveRemotePort(cfg));
    }

    private @NotNull String resolveRemoteHost(@Nullable ZaFridaProjectConfig cfg) {
        if (cfg != null && ZaStrUtil.isNotBlank(cfg.remoteHost)) {
            return cfg.remoteHost.trim();
        }
        ZaFridaSettingsState st = ApplicationManager.getApplication()
                .getService(ZaFridaSettingsService.class)
                .getState();
        return ZaFridaNetUtil.defaultHost(st.defaultRemoteHost);
    }

    private int resolveRemotePort(@Nullable ZaFridaProjectConfig cfg) {
        if (cfg != null && cfg.remotePort > 0) {
            return cfg.remotePort;
        }
        ZaFridaSettingsState st = ApplicationManager.getApplication()
                .getService(ZaFridaSettingsService.class)
                .getState();
        return ZaFridaNetUtil.defaultPort(st.defaultRemotePort);
    }


    private void runFrida() {
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

    private void attachFrida() {
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
        FridaConnectionMode connectionMode;
        if (projectConfig != null && projectConfig.connectionMode != null) {
            connectionMode = projectConfig.connectionMode;
        } else {
            connectionMode = FridaConnectionMode.USB;
        }
        final FridaConnectionMode finalConnectionMode = connectionMode;
        final boolean gadgetMode = connectionMode == FridaConnectionMode.GADGET;

        FridaDevice dev = resolveDevice(projectConfig, connectionMode, gadgetMode);
        if (dev == null) {
            return;
        }

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

            FridaRunConfig cfg = new FridaRunConfig(
                    dev,
                    mode,
                    script.getPath(),
                    extraArgs
            );

            String fridaProjectDir = null;
            if (activeProjectDir != null && activeProjectDir.isValid()) {
                fridaProjectDir = activeProjectDir.getPath();
            }

            String targetPackage = null;
            if (!gadgetMode && !target.isEmpty()) {
                targetPackage = target;
            }

            ZaFridaConsolePanel console = runConsolePanel;
            consoleTabsPanel.showRunConsole();
            warnIfTypeScriptNeedsFrida17(script, console);
            String finalFridaProjectDir = fridaProjectDir;
            String finalTargetPackage = targetPackage;
            Runnable startSession = () ->
                    startFridaSession(ZaFridaSessionType.RUN, cfg, console, finalFridaProjectDir, finalTargetPackage);
            boolean needsAdbForward = (finalConnectionMode == FridaConnectionMode.REMOTE || gadgetMode)
                    && ZaFridaNetUtil.isLoopbackHost(resolveRemoteHost(projectConfig));
            if (needsAdbForward) {
                adbService.forwardTcp(
                        resolveRemotePort(projectConfig),
                        resolveAdbDeviceId(projectConfig),
                        console::info,
                        console::warn,
                        startSession
                );
                return;
            }

            startSession.run();
        });
    }

    private void attachFridaWithConfig(@Nullable ZaFridaFridaProject active,
                                       @Nullable ZaFridaProjectConfig projectConfig,
                                       @NotNull String target,
                                       @NotNull String extraArgs,
                                       @Nullable VirtualFile preferredScript) {
        FridaConnectionMode connectionMode;
        if (projectConfig != null && projectConfig.connectionMode != null) {
            connectionMode = projectConfig.connectionMode;
        } else {
            connectionMode = FridaConnectionMode.USB;
        }
        final FridaConnectionMode finalConnectionMode = connectionMode;
        final boolean gadgetMode = connectionMode == FridaConnectionMode.GADGET;

        FridaDevice dev = resolveDevice(projectConfig, connectionMode, gadgetMode);
        if (dev == null) {
            return;
        }

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

            FridaRunConfig cfg = new FridaRunConfig(
                    dev,
                    mode,
                    script.getPath(),
                    extraArgs
            );

            String fridaProjectDir = null;
            if (activeProjectDir != null && activeProjectDir.isValid()) {
                fridaProjectDir = activeProjectDir.getPath();
            }

            ZaFridaConsolePanel console = attachConsolePanel;
            consoleTabsPanel.showAttachConsole();
            warnIfTypeScriptNeedsFrida17(script, console);
            String targetPackage = null;
            if (!gadgetMode && !target.isEmpty()) {
                targetPackage = target;
            }
            String finalFridaProjectDir = fridaProjectDir;
            String finalTargetPackage = targetPackage;
            Runnable startSession = () ->
                    startFridaSession(ZaFridaSessionType.ATTACH, cfg, console, finalFridaProjectDir, finalTargetPackage);
            boolean needsAdbForward = (finalConnectionMode == FridaConnectionMode.REMOTE || gadgetMode)
                    && ZaFridaNetUtil.isLoopbackHost(resolveRemoteHost(projectConfig));
            if (needsAdbForward) {
                adbService.forwardTcp(
                        resolveRemotePort(projectConfig),
                        resolveAdbDeviceId(projectConfig),
                        console::info,
                        console::warn,
                        startSession
                );
                return;
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

    private @Nullable FridaDevice resolveDevice(@Nullable ZaFridaProjectConfig projectConfig,
                                                @NotNull FridaConnectionMode connectionMode,
                                                boolean gadgetMode) {
        if (connectionMode == FridaConnectionMode.REMOTE || gadgetMode) {
            String hostValue = resolveRemoteHost(projectConfig);
            int portValue = resolveRemotePort(projectConfig);
            String host = String.format("%s:%s", hostValue, portValue);
            String type = "remote";
            String name = "Remote";
            if (gadgetMode) {
                type = "gadget";
                name = "Gadget";
            }
            return new FridaDevice(String.format("%s:%s", type, host), type, name, FridaDeviceMode.HOST, host);
        }
        FridaDevice dev = (FridaDevice) deviceCombo.getSelectedItem();
        if (dev == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "No device selected");
            return null;
        }
        return dev;
    }

    private @Nullable FridaDevice getSelectedDeviceForDiagnostics() {
        return (FridaDevice) deviceCombo.getSelectedItem();
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
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        String targetRaw = targetField.getText();
        String targetText;
        if (targetRaw == null) {
            targetText = "";
        } else {
            targetText = targetRaw.trim();
        }
        if (active == null) {
            forceStopWithConfig(null, targetText);
            return;
        }
        fridaProjectManager.loadProjectConfigAsync(active, cfg -> forceStopWithConfig(cfg, targetText));
    }

    private void openApp() {
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        String targetRaw = targetField.getText();
        String targetText;
        if (targetRaw == null) {
            targetText = "";
        } else {
            targetText = targetRaw.trim();
        }
        if (active == null) {
            openAppWithConfig(null, targetText);
            return;
        }
        fridaProjectManager.loadProjectConfigAsync(active, cfg -> openAppWithConfig(cfg, targetText));
    }

    private void forceStopWithConfig(@Nullable ZaFridaProjectConfig projectConfig, @NotNull String targetText) {
        String packageName = resolveForceStopPackage(projectConfig, targetText);
        if (ZaStrUtil.isBlank(packageName)) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Force stop requires a package name");
            runConsolePanel.warn("[ZAFrida] Force stop requires a package name.");
            return;
        }

        FridaDevice selected = (FridaDevice) deviceCombo.getSelectedItem();
        String deviceId = null;
        if (selected != null && selected.getMode() == FridaDeviceMode.DEVICE_ID) {
            String id = selected.getId();
            if (ZaStrUtil.isNotBlank(id) && !"usb".equalsIgnoreCase(id)) {
                deviceId = id;
            }
        }
        adbService.forceStop(packageName, deviceId, runConsolePanel::info, runConsolePanel::error);
    }

    private void openAppWithConfig(@Nullable ZaFridaProjectConfig projectConfig, @NotNull String targetText) {
        String packageName = resolveForceStopPackage(projectConfig, targetText);
        if (ZaStrUtil.isBlank(packageName)) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Open app requires a package name");
            runConsolePanel.warn("[ZAFrida] Open app requires a package name.");
            return;
        }

        FridaDevice selected = (FridaDevice) deviceCombo.getSelectedItem();
        String deviceId = null;
        if (selected != null && selected.getMode() == FridaDeviceMode.DEVICE_ID) {
            String id = selected.getId();
            if (ZaStrUtil.isNotBlank(id) && !"usb".equalsIgnoreCase(id)) {
                deviceId = id;
            }
        }
        adbService.openApp(packageName, deviceId, runConsolePanel::info, runConsolePanel::error);
    }

    private @Nullable String resolveForceStopPackage(@Nullable ZaFridaProjectConfig cfg, @NotNull String targetText) {
        boolean gadgetMode = cfg != null && cfg.connectionMode == FridaConnectionMode.GADGET;
        String target = targetText;
        if (gadgetMode) {
            target = "";
        }
        if (!target.isEmpty()) {
            if (!ZaFridaTextUtil.isNumeric(target)) {
                return target;
            }
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

    private @Nullable String resolveAdbDeviceId(@Nullable ZaFridaProjectConfig config) {
        if (config == null || ZaStrUtil.isBlank(config.lastDeviceId)) {
            return null;
        }
        String deviceId = config.lastDeviceId.trim();
        if ("usb".equalsIgnoreCase(deviceId)) {
            return null;
        }
        return deviceId;
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

    private void disableControls(boolean disabled) {
        deviceCombo.setEnabled(!disabled);
        refreshDevicesBtn.setEnabled(!disabled);
        addRemoteBtn.setEnabled(!disabled);
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
