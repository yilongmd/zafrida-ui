package com.zafrida.ui.ui;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.fileChooser.FileChooser;
import com.intellij.openapi.fileChooser.FileChooserDescriptor;
import com.intellij.openapi.project.Project;
import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.execution.process.CapturingProcessHandler;
import com.intellij.execution.process.ProcessOutput;
import com.intellij.icons.AllIcons;
import com.intellij.openapi.options.ShowSettingsUtil;
import com.intellij.openapi.ui.ComboBox;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.vfs.LocalFileSystem;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.util.SlowOperations;
import com.intellij.ui.components.JBTextField;
import com.zafrida.ui.frida.*;
import com.zafrida.ui.fridaproject.*;
import com.zafrida.ui.fridaproject.ui.CreateZaFridaProjectDialog;
import com.zafrida.ui.fridaproject.ui.ZaFridaProjectSettingsDialog;
import com.zafrida.ui.session.RunningSession;
import com.zafrida.ui.session.ZaFridaSessionService;
import com.zafrida.ui.python.ProjectPythonEnvResolver;
import com.zafrida.ui.python.PythonEnvInfo;
import com.zafrida.ui.ui.components.SearchableComboBoxPanel;
import com.zafrida.ui.ui.components.SimpleDocumentListener;
import com.zafrida.ui.ui.render.DeviceCellRenderer;
import com.zafrida.ui.util.ProjectFileUtil;
import com.zafrida.ui.util.ZaFridaIcons;
import com.zafrida.ui.util.ZaFridaNotifier;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.settings.ZaFridaSettingsState;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import com.intellij.openapi.util.text.StringUtil;

/**
 * [UI组件] 运行控制主面板。
 * <p>
 * <strong>功能聚合：</strong>
 * 集成了设备选择、脚本选择、目标设置以及运行控制按钮。
 * <p>
 * <strong>数据流：</strong>
 * UI 操作 -> 更新 {@link ZaFridaProjectConfig} -> 调用 {@link FridaCliService} 执行命令。
 * <p>
 * <strong>注意：</strong>
 * 刷新设备列表操作 {@link #reloadDevicesAsync()} 必须在后台线程执行，避免阻塞 EDT。
 */
public final class ZaFridaRunPanel extends JPanel implements Disposable {

    private final @NotNull Project project;
    private final @NotNull ZaFridaConsolePanel consolePanel;
    private final @NotNull ZaFridaTemplatePanel templatePanel;

    private final @NotNull FridaCliService fridaCli;
    private final @NotNull ZaFridaSessionService sessionService;

    private final ComboBox<FridaDevice> deviceCombo = new ComboBox<>();
    private final JButton refreshDevicesBtn = new JButton("");
    private final JButton addRemoteBtn = new JButton("Remote");

    private final JBTextField runScriptField = new JBTextField();
    private final JButton locateRunScriptBtn = new JButton("");
    private final JButton chooseRunScriptBtn = new JButton("Choose...");
    private final JBTextField attachScriptField = new JBTextField();
    private final JButton locateAttachScriptBtn = new JButton("");
    private final JButton chooseAttachScriptBtn = new JButton("Choose...");

    private final JBTextField targetField = new JBTextField();

    private final JBTextField extraArgsField = new JBTextField();

    private final JButton runBtn = new JButton("Run");
    private final JButton attachBtn = new JButton("Attach");
    private final JButton stopBtn = new JButton("Stop");
    private final JButton forceStopBtn = new JButton("Force Stop App");
    private final JButton openAppBtn = new JButton("Open App");
    private final JButton clearConsoleBtn = new JButton("Clear Console");

    private final JLabel logFileLabel = new JLabel("Log: (not started)");

    private @Nullable VirtualFile runScriptFile;
    private @Nullable VirtualFile attachScriptFile;

    private boolean printedToolchainInfo = false;

    private final ZaFridaProjectManager fridaProjectManager;
    private final SearchableComboBoxPanel<ZaFridaFridaProject> fridaProjectSelector =
            new SearchableComboBoxPanel<>(p -> p == null ? "" : p.getName());
    private final JLabel projectTypeIcon = new JLabel();
    private boolean updatingFridaProjectSelector = false;
    private boolean updatingDeviceCombo = false;
    private boolean updatingRunFields = false;
    private @Nullable JButton externalRunBtn;
    private @Nullable JButton externalStopBtn;


    public ZaFridaRunPanel(@NotNull Project project,
                           @NotNull ZaFridaConsolePanel consolePanel,
                           @NotNull ZaFridaTemplatePanel templatePanel) {
        super(new BorderLayout());
        this.project = project;
        this.consolePanel = consolePanel;
        this.templatePanel = templatePanel;

        this.fridaCli = ApplicationManager.getApplication().getService(FridaCliService.class);
        this.sessionService = project.getService(ZaFridaSessionService.class);
        this.fridaProjectManager = project.getService(ZaFridaProjectManager.class);


        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 8, 6, 8);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;

        int row = 0;
        row = addRow(form, row, new JLabel("Project"), buildFridaProjectRow());
        row = addRow(form, row, new JLabel("Device"), buildDeviceRow());
        row = addRow(form, row, new JLabel("Run Script"), buildRunScriptRow());
        row = addRow(form, row, new JLabel("Attach Script"), buildAttachScriptRow());
        row = addRow(form, row, new JLabel("Target"), buildTargetRow());
        row = addRow(form, row, new JLabel("Extra"), buildExtraRow());
        row = addRow(form, row, new JLabel(""), buildButtonsRow());

        add(form, BorderLayout.NORTH);
        add(logFileLabel, BorderLayout.SOUTH);

        initUiState();
        bindActions();
        subscribeToFridaProjectChanges();
        reloadFridaProjectsIntoUi();
        applyActiveFridaProjectToUi(fridaProjectManager.getActiveProject());
    }

    private void initUiState() {
        deviceCombo.setRenderer(new DeviceCellRenderer());
        runScriptField.setEditable(false);
        attachScriptField.setEditable(false);
        extraArgsField.setToolTipText("Extra args passed to frida, e.g. --realm=emulated");
        projectTypeIcon.setToolTipText("Project platform");

        targetField.setColumns(18);
        extraArgsField.setColumns(18);
        targetField.setToolTipText("Spawn uses package name; Attach uses PID");

        refreshDevicesBtn.setIcon(AllIcons.Actions.Refresh);
        addRemoteBtn.setIcon(AllIcons.General.Add);
        locateRunScriptBtn.setIcon(AllIcons.General.Locate);
        locateRunScriptBtn.setToolTipText("Locate run script in Project View");
        chooseRunScriptBtn.setIcon(AllIcons.Actions.MenuOpen);
        locateAttachScriptBtn.setIcon(AllIcons.General.Locate);
        locateAttachScriptBtn.setToolTipText("Locate attach script in Project View");
        chooseAttachScriptBtn.setIcon(AllIcons.Actions.MenuOpen);
        runBtn.setIcon(AllIcons.Actions.Execute);
        attachBtn.setIcon(AllIcons.Actions.Execute);
        stopBtn.setIcon(AllIcons.Actions.Suspend);
        forceStopBtn.setIcon(AllIcons.Actions.Cancel);
        openAppBtn.setIcon(AllIcons.Actions.Execute);
        clearConsoleBtn.setIcon(AllIcons.Actions.ClearCash);
        setRunningState(false);
    }

    private JPanel buildFridaProjectRow() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        row.add(projectTypeIcon);
        row.add(fridaProjectSelector);
        return row;
    }

    private void bindActions() {
        refreshDevicesBtn.addActionListener(e -> reloadDevicesAsync());

        addRemoteBtn.addActionListener(e -> {
            ZaFridaSettingsState st = ApplicationManager.getApplication()
                    .getService(ZaFridaSettingsService.class)
                    .getState();
            String defHost = safeHost(st.defaultRemoteHost);
            int defPort = safePort(st.defaultRemotePort);
            String initial = defHost + ":" + defPort;

            String host = Messages.showInputDialog(this, "host:port", "Add Frida Remote Host", null, initial, null);
            if (host == null) return;
            String h = host.trim();
            if (h.isEmpty()) return;
            ApplicationManager.getApplication().getService(ZaFridaSettingsService.class).addRemoteHost(h);
            reloadDevicesAsync();
        });

        clearConsoleBtn.addActionListener(e -> consolePanel.clear());

        runBtn.addActionListener(e -> runFrida());
        attachBtn.addActionListener(e -> attachFrida());
        stopBtn.addActionListener(e -> stopFrida());
        forceStopBtn.addActionListener(e -> forceStopApp());
        openAppBtn.addActionListener(e -> openApp());

        deviceCombo.addActionListener(e -> {
            if (updatingDeviceCombo) return;
            FridaDevice selected = (FridaDevice) deviceCombo.getSelectedItem();
            if (selected == null) return;
            ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
            if (active == null) return;
            fridaProjectManager.updateProjectConfig(active, cfg -> {
                if (selected.getMode() == FridaDeviceMode.HOST) {
                    cfg.lastDeviceHost = selected.getHost();
                    cfg.lastDeviceId = null;
                } else {
                    cfg.lastDeviceId = selected.getId();
                    cfg.lastDeviceHost = null;
                }
            });
        });

        fridaProjectSelector.addActionListener(e -> {
            if (updatingFridaProjectSelector) return;
            fridaProjectManager.setActiveProject(fridaProjectSelector.getSelectedItem());
        });

        extraArgsField.getDocument().addDocumentListener(new SimpleDocumentListener(this::persistExtraArgs));

        chooseRunScriptBtn.addActionListener(e -> {
            ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
            VirtualFile initial = active != null ? fridaProjectManager.resolveProjectDir(active) : null;
            VirtualFile file = chooseRunScriptFile(initial);
            if (file == null) return;

            setRunScriptFile(file);

            if (active != null) {
                String rel = fridaProjectManager.toProjectRelativePath(active, file);
                if (rel != null) fridaProjectManager.updateProjectConfig(active, c -> c.mainScript = rel);
            }
        });

        chooseAttachScriptBtn.addActionListener(e -> {
            ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
            VirtualFile initial = active != null ? fridaProjectManager.resolveProjectDir(active) : null;
            VirtualFile file = chooseAttachScriptFile(initial);
            if (file == null) return;

            setAttachScriptFile(file);

            if (active != null) {
                String rel = fridaProjectManager.toProjectRelativePath(active, file);
                if (rel != null) fridaProjectManager.updateProjectConfig(active, c -> c.attachScript = rel);
            }
        });

        locateRunScriptBtn.addActionListener(e -> locateRunScriptInProjectView());
        locateAttachScriptBtn.addActionListener(e -> locateAttachScriptInProjectView());

    }

    private void subscribeToFridaProjectChanges() {
        // 用面板本身作为 Disposable，IDE 关闭 ToolWindow 时会自动断开订阅
        project.getMessageBus().connect(this).subscribe(ZaFridaProjectManager.TOPIC, new ZaFridaProjectListener() {
            @Override
            public void onActiveProjectChanged(@Nullable ZaFridaFridaProject newProject) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    // 项目列表可能被新增/导入，所以这里顺手刷新 selector items
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

            // 没有项目时，禁用一些按钮（可选）
            boolean has = !list.isEmpty();
            fridaProjectSelector.setEnabled(true);

            if (!has) {
                // 这里不强制清空脚本/target，避免用户临时用“无项目模式”
            }
        } finally {
            updatingFridaProjectSelector = false;
        }
    }
    private void applyActiveFridaProjectToUi(@Nullable ZaFridaFridaProject active) {
        updatingFridaProjectSelector = true;
        try {
            fridaProjectSelector.setSelectedItem(active);
        } finally {
            updatingFridaProjectSelector = false;
        }

        updateProjectTypeIcon(active);
        templatePanel.setCurrentPlatform(active == null ? null : active.getPlatform());

        if (active == null) {
            // 不强制清空，让用户仍可用“自由脚本模式”
            targetField.setEnabled(true);
            targetField.setToolTipText(null);
            reloadDevicesAsync();
            return;
        }

        ZaFridaProjectConfig cfg = fridaProjectManager.loadProjectConfig(active);

        updatingRunFields = true;
        try {
            extraArgsField.setText(cfg.extraArgs == null ? "" : cfg.extraArgs);
        } finally {
            updatingRunFields = false;
        }

        // 1) 恢复 lastTarget（由设置页保存）
        if (!StringUtil.isEmptyOrSpaces(cfg.lastTarget)) {
            targetField.setText(cfg.lastTarget);
        }

        applyConnectionUi(cfg);

        // 2) 恢复 mainScript/attachScript（项目内相对路径）
        VirtualFile dir = fridaProjectManager.resolveProjectDir(active);
        if (dir != null) {
            String rel = cfg.mainScript;
            if (!StringUtil.isEmptyOrSpaces(rel)) {
                final VirtualFile[] fRef = new VirtualFile[1];
                SlowOperations.allowSlowOperations(() -> fRef[0] = dir.findFileByRelativePath(rel));
                VirtualFile f = fRef[0];
                if (f != null && !f.isDirectory()) {
                    setRunScriptFile(f);
                } else {
                    // mainScript 丢失时给个提示，不强制创建，避免误操作
                    consolePanel.warn("[ZAFrida] Main script not found in project: " + rel);
                }
            }
            String attachRel = cfg.attachScript;
            if (!StringUtil.isEmptyOrSpaces(attachRel)) {
                final VirtualFile[] attachRef = new VirtualFile[1];
                SlowOperations.allowSlowOperations(() -> attachRef[0] = dir.findFileByRelativePath(attachRel));
                VirtualFile f = attachRef[0];
                if (f != null && !f.isDirectory()) {
                    setAttachScriptFile(f);
                } else {
                    consolePanel.warn("[ZAFrida] Attach script not found in project: " + attachRel);
                }
            } else {
                attachScriptFile = null;
                attachScriptField.setText("");
            }
        }

        reloadDevicesAsync();
    }

    private void updateProjectTypeIcon(@Nullable ZaFridaFridaProject active) {
        if (active == null) {
            projectTypeIcon.setIcon(null);
            projectTypeIcon.setToolTipText("No active project");
            return;
        }
        projectTypeIcon.setIcon(ZaFridaIcons.forPlatform(active.getPlatform()));
        projectTypeIcon.setToolTipText("Platform: " + active.getPlatform().name());
    }

    private void persistExtraArgs() {
        if (updatingRunFields) return;
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        if (active == null) return;
        String args = extraArgsField.getText();
        fridaProjectManager.updateProjectConfig(active, c -> c.extraArgs = args == null ? "" : args);
    }

    private @Nullable VirtualFile chooseRunScriptFile(@Nullable VirtualFile initialDir) {
        ZaFridaSettingsState st = ApplicationManager.getApplication()
                .getService(ZaFridaSettingsService.class)
                .getState();
        if (st.useIdeScriptChooser) {
            return ProjectFileUtil.chooseJavaScriptFileInProject(project, initialDir);
        }

        if (initialDir != null) {
            FileChooserDescriptor d = new FileChooserDescriptor(true, false, false, false, false, false);
            d.withFileFilter(vf -> "js".equalsIgnoreCase(vf.getExtension()));
            VirtualFile picked = FileChooser.chooseFile(d, project, initialDir);
            if (picked != null) return picked;
        }
        return ProjectFileUtil.chooseJavaScriptFile(project);
    }

    private @Nullable VirtualFile chooseAttachScriptFile(@Nullable VirtualFile initialDir) {
        return chooseRunScriptFile(initialDir);
    }
    private void createNewFridaProject() {
        CreateZaFridaProjectDialog dialog = new CreateZaFridaProjectDialog(project);
        if (!dialog.showAndGet()) return;

        String name = dialog.getProjectName();
        if (name.isEmpty()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Project name is empty");
            return;
        }

        ZaFridaPlatform platform = dialog.getPlatform();

        try {
            ZaFridaFridaProject created = fridaProjectManager.createAndActivate(name, platform);

            reloadFridaProjectsIntoUi();
            applyActiveFridaProjectToUi(created);

            consolePanel.info("[ZAFrida] Created project: " + created.getName() + " (" + created.getRelativeDir() + ")");
        } catch (Throwable t) {
            consolePanel.error("[ZAFrida] Create project failed: " + t.getMessage());
            ZaFridaNotifier.error(project, "ZAFrida", "Create project failed: " + t.getMessage());
        }
    }

    private void openProjectSettings() {
        ZaFridaProjectSettingsDialog dialog = new ZaFridaProjectSettingsDialog(
                project,
                fridaProjectManager,
                fridaCli,
                () -> (FridaDevice) deviceCombo.getSelectedItem(),
                consolePanel::error
        );
        if (dialog.showAndGet()) {
            applyActiveFridaProjectToUi(fridaProjectManager.getActiveProject());
        }
    }

    private void openGlobalSettings() {
        SlowOperations.allowSlowOperations(() ->
                ShowSettingsUtil.getInstance().showSettingsDialog(project, "ZAFrida")
        );
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

    public void showLanguageToggleMessage() {
        Messages.showInfoMessage(
                project,
                "Switch UI language (中文/English) is coming soon.",
                "ZAFrida"
        );
    }

    public void triggerRun() {
        if (!runBtn.isEnabled()) return;
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

    public void triggerAttach() {
        if (!attachBtn.isEnabled()) return;
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

    public void triggerStop() {
        if (!stopBtn.isEnabled()) return;
        stopFrida();
    }

    public void triggerForceStop() {
        forceStopApp();
    }

    public void triggerClearConsole() {
        consolePanel.clear();
    }

    public void bindExternalRunStopButtons(@NotNull JButton runButton, @NotNull JButton stopButton) {
        this.externalRunBtn = runButton;
        this.externalStopBtn = stopButton;
        syncExternalRunStopButtons();
    }






    private JPanel buildDeviceRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        deviceCombo.setPrototypeDisplayValue(new FridaDevice("usb", "usb", "Android"));
        p.add(deviceCombo);
        p.add(refreshDevicesBtn);
        p.add(addRemoteBtn);
        return p;
    }


    private JPanel buildRunScriptRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        runScriptField.setColumns(22);
        p.add(runScriptField);
        p.add(locateRunScriptBtn);
        p.add(chooseRunScriptBtn);
        return p;
    }

    private JPanel buildAttachScriptRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        attachScriptField.setColumns(22);
        p.add(attachScriptField);
        p.add(locateAttachScriptBtn);
        p.add(chooseAttachScriptBtn);
        return p;
    }

    private JPanel buildTargetRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        p.add(targetField);
        return p;
    }

    private JPanel buildExtraRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        p.add(new JLabel("Args:"));
        p.add(extraArgsField);
        return p;
    }

    private JPanel buildButtonsRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        p.add(runBtn);
        p.add(attachBtn);
        p.add(stopBtn);
        p.add(forceStopBtn);
        p.add(openAppBtn);
        p.add(clearConsoleBtn);
        return p;
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
        this.runScriptField.setText(file.getPath());
        this.templatePanel.setCurrentScriptFile(file);
    }

    private void setAttachScriptFile(@NotNull VirtualFile file) {
        this.attachScriptFile = file;
        this.attachScriptField.setText(file.getPath());
    }

    private void locateRunScriptInProjectView() {
        String path = runScriptField.getText();
        VirtualFile file = resolveRunScriptFileForLocate();
        if (file == null || !file.isValid() || file.isDirectory()) {
            if (StringUtil.isEmptyOrSpaces(path)) {
                ZaFridaNotifier.warn(project, "ZAFrida", "No script file selected");
            } else {
                ZaFridaNotifier.warn(project, "ZAFrida", "Script file not found: " + path.trim());
            }
            return;
        }
        ProjectFileUtil.openAndSelectInProject(project, file);
    }

    private void locateAttachScriptInProjectView() {
        String path = attachScriptField.getText();
        VirtualFile file = resolveAttachScriptFileForLocate();
        if (file == null || !file.isValid() || file.isDirectory()) {
            if (StringUtil.isEmptyOrSpaces(path)) {
                ZaFridaNotifier.warn(project, "ZAFrida", "No attach script file selected");
            } else {
                ZaFridaNotifier.warn(project, "ZAFrida", "Attach script file not found: " + path.trim());
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
        if (StringUtil.isEmptyOrSpaces(path)) return null;
        return LocalFileSystem.getInstance().findFileByPath(path.trim());
    }

    private @Nullable VirtualFile resolveAttachScriptFileForLocate() {
        if (attachScriptFile != null && attachScriptFile.isValid()) {
            return attachScriptFile;
        }
        String path = attachScriptField.getText();
        if (StringUtil.isEmptyOrSpaces(path)) return null;
        return LocalFileSystem.getInstance().findFileByPath(path.trim());
    }


    private void printToolchainInfoOnce() {
        if (printedToolchainInfo) return;
        printedToolchainInfo = true;

        PythonEnvInfo env = ProjectPythonEnvResolver.resolve(project);
        if (env == null) {
            consolePanel.warn("[ZAFrida] Project Python interpreter env not detected. Using IDE/system PATH for frida-tools.");
            return;
        }

        consolePanel.info("[ZAFrida] Project Python: " + env.getPythonHome());
        if (!env.getPathEntries().isEmpty()) {
            consolePanel.info("[ZAFrida] Project PATH prepend: " + String.join(File.pathSeparator, env.getPathEntries()));
        }

        ZaFridaSettingsState st = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class).getState();
        String ls = ProjectPythonEnvResolver.findTool(env, st.fridaLsDevicesExecutable);
        String ps = ProjectPythonEnvResolver.findTool(env, st.fridaPsExecutable);
        String frida = ProjectPythonEnvResolver.findTool(env, st.fridaExecutable);

        if (ls != null) {
            consolePanel.info("[ZAFrida] Resolved frida-ls-devices: " + ls);
        } else {
            consolePanel.warn("[ZAFrida] frida-ls-devices not found in project interpreter; will fallback to system PATH if available.");
        }
        if (ps != null) {
            consolePanel.info("[ZAFrida] Resolved frida-ps: " + ps);
        }
        if (frida != null) {
            consolePanel.info("[ZAFrida] Resolved frida: " + frida);
        }
    }

    private void reloadDevicesAsync() {
        disableControls(true);
        printToolchainInfoOnce();
        consolePanel.info("[ZAFrida] Loading devices...");

        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        ZaFridaProjectConfig cfg = active != null ? fridaProjectManager.loadProjectConfig(active) : null;
        FridaConnectionMode connectionMode =
                cfg != null && cfg.connectionMode != null ? cfg.connectionMode : FridaConnectionMode.USB;

        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                List<FridaDevice> devices = new ArrayList<>(fridaCli.listDevices(project));
                // add remotes from settings
                var settingsService = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
                var remotes = settingsService.getRemoteHosts();
                for (String host : remotes) {
                    if (!containsHost(devices, host)) {
                        devices.add(new FridaDevice("remote:" + host, "remote", "Remote", FridaDeviceMode.HOST, host));
                    }
                }

                if (cfg != null && (connectionMode == FridaConnectionMode.REMOTE || connectionMode == FridaConnectionMode.GADGET)) {
                    String host = resolveHostPort(cfg);
                    if (!containsHost(devices, host)) {
                        String type = connectionMode == FridaConnectionMode.GADGET ? "gadget" : "remote";
                        String name = connectionMode == FridaConnectionMode.GADGET ? "Gadget" : "Remote";
                        devices.add(new FridaDevice(type + ":" + host, type, name, FridaDeviceMode.HOST, host));
                    }
                }

                ApplicationManager.getApplication().invokeLater(() -> {
                    updatingDeviceCombo = true;
                    try {
                        deviceCombo.removeAllItems();
                        for (FridaDevice d : devices) deviceCombo.addItem(d);
                        selectSavedDevice(devices, cfg);
                    } finally {
                        updatingDeviceCombo = false;
                    }
                    consolePanel.info("[ZAFrida] Devices loaded: " + devices.size());
                    disableControls(false);
                });
            } catch (Throwable t) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    consolePanel.error("[ZAFrida] Load devices failed: " + t.getMessage());
                    disableControls(false);
                });
            }
        });
    }

    private void applyConnectionUi(@NotNull ZaFridaProjectConfig cfg) {
        FridaConnectionMode mode = cfg.connectionMode != null ? cfg.connectionMode : FridaConnectionMode.USB;
        boolean gadgetMode = mode == FridaConnectionMode.GADGET;
        targetField.setEnabled(!gadgetMode);
        if (gadgetMode) {
            targetField.setToolTipText("Gadget mode uses -F; target is ignored.");
        } else {
            targetField.setToolTipText(null);
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
                if (!StringUtil.isEmptyOrSpaces(cfg.lastDeviceHost)) {
                    match = findDeviceByHost(devices, cfg.lastDeviceHost);
                } else if (!StringUtil.isEmptyOrSpaces(cfg.lastDeviceId)) {
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

    private @NotNull String resolveHostPort(@Nullable ZaFridaProjectConfig cfg) {
        return resolveRemoteHost(cfg) + ":" + resolveRemotePort(cfg);
    }

    private @NotNull String resolveRemoteHost(@Nullable ZaFridaProjectConfig cfg) {
        if (cfg != null && !StringUtil.isEmptyOrSpaces(cfg.remoteHost)) {
            return cfg.remoteHost.trim();
        }
        ZaFridaSettingsState st = ApplicationManager.getApplication()
                .getService(ZaFridaSettingsService.class)
                .getState();
        return safeHost(st.defaultRemoteHost);
    }

    private int resolveRemotePort(@Nullable ZaFridaProjectConfig cfg) {
        if (cfg != null && cfg.remotePort > 0) {
            return cfg.remotePort;
        }
        ZaFridaSettingsState st = ApplicationManager.getApplication()
                .getService(ZaFridaSettingsService.class)
                .getState();
        return safePort(st.defaultRemotePort);
    }

    private static @NotNull String safeHost(@Nullable String host) {
        if (host == null || host.isBlank()) return "127.0.0.1";
        return host.trim();
    }

    private static boolean isLoopbackHost(@Nullable String host) {
        if (host == null) return false;
        String trimmed = host.trim();
        return "127.0.0.1".equals(trimmed) || "localhost".equalsIgnoreCase(trimmed);
    }

    private static int safePort(int port) {
        return port > 0 ? port : 14725;
    }


    private void runFrida() {
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        ZaFridaProjectConfig projectConfig = active != null ? fridaProjectManager.loadProjectConfig(active) : null;
        FridaConnectionMode connectionMode = projectConfig != null && projectConfig.connectionMode != null
                ? projectConfig.connectionMode
                : FridaConnectionMode.USB;
        boolean gadgetMode = connectionMode == FridaConnectionMode.GADGET;

        FridaDevice dev = resolveDevice(projectConfig, connectionMode, gadgetMode);
        if (dev == null) return;

        String target = targetField.getText() != null ? targetField.getText().trim() : "";
        if (!gadgetMode && target.isEmpty()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Target is empty");
            return;
        }

        VirtualFile script = resolveRunScript(active, target, gadgetMode);
        if (script == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Choose a run script file first");
            return;
        }

        if (active != null && !gadgetMode) {
            fridaProjectManager.updateProjectConfig(active, c -> c.lastTarget = target);
        }
        if (active != null) {
            String rel = fridaProjectManager.toProjectRelativePath(active, script);
            if (rel != null) {
                fridaProjectManager.updateProjectConfig(active, c -> c.mainScript = rel);
            }
        }

        FridaRunMode mode = gadgetMode ? new FrontmostRunMode() : new SpawnRunMode(target);

        FridaRunConfig cfg = new FridaRunConfig(
                dev,
                mode,
                script.getPath(),
                extraArgsField.getText() != null ? extraArgsField.getText() : ""
        );

        // 确定 Frida 项目目录
        String fridaProjectDir = null;
        if (active != null) {
            VirtualFile dir = fridaProjectManager.resolveProjectDir(active);
            if (dir != null) {
                fridaProjectDir = dir.getPath();
            }
        }

        // 确定包名（spawn 模式下的 target）
        String targetPackage = null;
        if (!gadgetMode && !target.isEmpty()) {
            targetPackage = target;
        }

        final String finalFridaProjectDir = fridaProjectDir;
        final String finalTargetPackage = targetPackage;
        Runnable startSession = () -> startFridaSession(cfg, finalFridaProjectDir, finalTargetPackage);
        boolean needsAdbForward = (connectionMode == FridaConnectionMode.REMOTE || gadgetMode)
                && isLoopbackHost(resolveRemoteHost(projectConfig));
        if (needsAdbForward) {
            runAdbForward(resolveRemotePort(projectConfig), startSession);
            return;
        }

        startSession.run();
    }

    private void attachFrida() {
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        ZaFridaProjectConfig projectConfig = active != null ? fridaProjectManager.loadProjectConfig(active) : null;
        FridaConnectionMode connectionMode = projectConfig != null && projectConfig.connectionMode != null
                ? projectConfig.connectionMode
                : FridaConnectionMode.USB;
        boolean gadgetMode = connectionMode == FridaConnectionMode.GADGET;

        FridaDevice dev = resolveDevice(projectConfig, connectionMode, gadgetMode);
        if (dev == null) return;

        String target = targetField.getText() != null ? targetField.getText().trim() : "";
        if (!gadgetMode && target.isEmpty()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Target is empty");
            return;
        }

        VirtualFile script = resolveAttachScript(active);
        if (script == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Choose an attach script file first");
            return;
        }

        if (active != null) {
            String rel = fridaProjectManager.toProjectRelativePath(active, script);
            if (rel != null) {
                fridaProjectManager.updateProjectConfig(active, c -> c.attachScript = rel);
            }
        }

        FridaRunMode mode;
        if (gadgetMode) {
            mode = new FrontmostRunMode();
        } else {
            try {
                mode = new AttachPidRunMode(Integer.parseInt(target));
            } catch (NumberFormatException e) {
                ZaFridaNotifier.warn(project, "ZAFrida", "Attach requires PID integer");
                return;
            }
        }

        FridaRunConfig cfg = new FridaRunConfig(
                dev,
                mode,
                script.getPath(),
                extraArgsField.getText() != null ? extraArgsField.getText() : ""
        );

        String fridaProjectDir = null;
        if (active != null) {
            VirtualFile dir = fridaProjectManager.resolveProjectDir(active);
            if (dir != null) {
                fridaProjectDir = dir.getPath();
            }
        }

        final String finalFridaProjectDir = fridaProjectDir;
        Runnable startSession = () -> startFridaSession(cfg, finalFridaProjectDir, null);
        boolean needsAdbForward = (connectionMode == FridaConnectionMode.REMOTE || gadgetMode)
                && isLoopbackHost(resolveRemoteHost(projectConfig));
        if (needsAdbForward) {
            runAdbForward(resolveRemotePort(projectConfig), startSession);
            return;
        }

        startSession.run();
    }

    private @Nullable FridaDevice resolveDevice(@Nullable ZaFridaProjectConfig projectConfig,
                                                @NotNull FridaConnectionMode connectionMode,
                                                boolean gadgetMode) {
        if (connectionMode == FridaConnectionMode.REMOTE || gadgetMode) {
            String hostValue = resolveRemoteHost(projectConfig);
            int portValue = resolveRemotePort(projectConfig);
            String host = hostValue + ":" + portValue;
            String type = gadgetMode ? "gadget" : "remote";
            String name = gadgetMode ? "Gadget" : "Remote";
            return new FridaDevice(type + ":" + host, type, name, FridaDeviceMode.HOST, host);
        }
        FridaDevice dev = (FridaDevice) deviceCombo.getSelectedItem();
        if (dev == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "No device selected");
            return null;
        }
        return dev;
    }

    private @Nullable VirtualFile resolveRunScript(@Nullable ZaFridaFridaProject active,
                                                   @NotNull String target,
                                                   boolean gadgetMode) {
        VirtualFile script = runScriptFile != null ? runScriptFile : templatePanel.getCurrentScriptFile();

        if (script == null && active != null) {
            ZaFridaProjectConfig pc = fridaProjectManager.loadProjectConfig(active);
            VirtualFile dir = fridaProjectManager.resolveProjectDir(active);
            if (dir != null && pc != null && !StringUtil.isEmptyOrSpaces(pc.mainScript)) {
                VirtualFile cand = dir.findFileByRelativePath(pc.mainScript);
                if (cand != null && !cand.isDirectory()) {
                    setRunScriptFile(cand);
                    script = cand;
                }
            }
        }

        if (script == null && active != null && !gadgetMode) {
            VirtualFile auto = fridaProjectManager.ensureMainScriptForTarget(active, target);
            setRunScriptFile(auto);
            script = auto;
        }

        return script;
    }

    private @Nullable VirtualFile resolveAttachScript(@Nullable ZaFridaFridaProject active) {
        VirtualFile script = attachScriptFile;

        if (script == null && active != null) {
            ZaFridaProjectConfig pc = fridaProjectManager.loadProjectConfig(active);
            VirtualFile dir = fridaProjectManager.resolveProjectDir(active);
            if (dir != null && pc != null && !StringUtil.isEmptyOrSpaces(pc.attachScript)) {
                VirtualFile cand = dir.findFileByRelativePath(pc.attachScript);
                if (cand != null && !cand.isDirectory()) {
                    setAttachScriptFile(cand);
                    script = cand;
                }
            }
        }

        return script;
    }

    private void startFridaSession(@NotNull FridaRunConfig cfg,
                                   @Nullable String fridaProjectDir,
                                   @Nullable String targetPackage) {
        try {
            RunningSession session = sessionService.start(
                    cfg,
                    consolePanel.getConsoleView(),
                    consolePanel::info,
                    consolePanel::error,
                    fridaProjectDir,
                    targetPackage
            );

            session.getProcessHandler().addProcessListener(sessionService.createUiStateListener(() -> {
                setRunningState(false);
            }));

            setRunningState(true);
            logFileLabel.setText("Log: " + session.getLogFilePath());
            consolePanel.info("[ZAFrida] Log file: " + session.getLogFilePath());
        } catch (Throwable t) {
            consolePanel.error("[ZAFrida] Start failed: " + t.getMessage());
            ZaFridaNotifier.error(project, "ZAFrida", "Start failed: " + t.getMessage());
        }
    }

    private void runAdbForward(int port, @NotNull Runnable onDone) {
        String tcp = "tcp:" + port;
        GeneralCommandLine cmd = new GeneralCommandLine("adb", "forward", tcp, tcp);
        consolePanel.info("[ZAFrida] ADB forward: " + cmd.getCommandLineString());

        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                CapturingProcessHandler handler = new CapturingProcessHandler(cmd);
                ProcessOutput out = handler.runProcess(10_000);
                String stdout = out.getStdout() != null ? out.getStdout().trim() : "";
                String stderr = out.getStderr() != null ? out.getStderr().trim() : "";
                int exitCode = out.getExitCode();

                ApplicationManager.getApplication().invokeLater(() -> {
                    if (exitCode != 0) {
                        consolePanel.warn("[ZAFrida] ADB forward failed (exitCode=" + exitCode + ")");
                    } else {
                        consolePanel.info("[ZAFrida] ADB forward ready on port " + port);
                    }
                    if (!stdout.isBlank()) {
                        consolePanel.info("[ZAFrida] " + stdout);
                    }
                    if (!stderr.isBlank()) {
                        consolePanel.warn("[ZAFrida] " + stderr);
                    }
                    onDone.run();
                });
            } catch (Throwable t) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    consolePanel.warn("[ZAFrida] ADB forward failed: " + t.getMessage());
                    onDone.run();
                });
            }
        });
    }

    private void stopFrida() {
        sessionService.stop();
        setRunningState(false);
        consolePanel.info("[ZAFrida] Stopped");
    }

    private void forceStopApp() {
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        ZaFridaProjectConfig projectConfig = active != null ? fridaProjectManager.loadProjectConfig(active) : null;
        String packageName = resolveForceStopPackage(projectConfig);
        if (StringUtil.isEmptyOrSpaces(packageName)) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Force stop requires a package name");
            consolePanel.warn("[ZAFrida] Force stop requires a package name.");
            return;
        }

        FridaDevice selected = (FridaDevice) deviceCombo.getSelectedItem();
        String deviceId = null;
        if (selected != null && selected.getMode() == FridaDeviceMode.DEVICE_ID) {
            String id = selected.getId();
            if (!StringUtil.isEmptyOrSpaces(id) && !"usb".equalsIgnoreCase(id)) {
                deviceId = id;
            }
        }

        List<String> args = new ArrayList<>();
        args.add("adb");
        if (deviceId != null) {
            args.add("-s");
            args.add(deviceId);
        }
        args.add("shell");
        args.add("am");
        args.add("force-stop");
        args.add(packageName);

        GeneralCommandLine cmd = new GeneralCommandLine(args);
        consolePanel.info("[ZAFrida] Force stop command: " + cmd.getCommandLineString());

        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                CapturingProcessHandler handler = new CapturingProcessHandler(cmd);
                ProcessOutput out = handler.runProcess(10_000);
                String stdout = out.getStdout() != null ? out.getStdout().trim() : "";
                String stderr = out.getStderr() != null ? out.getStderr().trim() : "";
                int exitCode = out.getExitCode();
                ApplicationManager.getApplication().invokeLater(() -> {
                    if (exitCode == 0) {
                        consolePanel.info("[ZAFrida] Force stopped: " + packageName);
                        if (!stdout.isBlank()) {
                            consolePanel.info(stdout);
                        }
                    } else {
                        String detail = !stderr.isBlank() ? stderr : stdout;
                        if (detail.isBlank()) detail = "unknown error";
                        consolePanel.error("[ZAFrida] Force stop failed (exit=" + exitCode + "): " + detail);
                    }
                });
            } catch (Throwable t) {
                ApplicationManager.getApplication().invokeLater(() ->
                        consolePanel.error("[ZAFrida] Force stop failed: " + t.getMessage())
                );
            }
        });
    }

    private void openApp() {
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        ZaFridaProjectConfig projectConfig = active != null ? fridaProjectManager.loadProjectConfig(active) : null;
        String packageName = resolveForceStopPackage(projectConfig);
        if (StringUtil.isEmptyOrSpaces(packageName)) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Open app requires a package name");
            consolePanel.warn("[ZAFrida] Open app requires a package name.");
            return;
        }

        FridaDevice selected = (FridaDevice) deviceCombo.getSelectedItem();
        String deviceId = null;
        if (selected != null && selected.getMode() == FridaDeviceMode.DEVICE_ID) {
            String id = selected.getId();
            if (!StringUtil.isEmptyOrSpaces(id) && !"usb".equalsIgnoreCase(id)) {
                deviceId = id;
            }
        }

        List<String> args = new ArrayList<>();
        args.add("adb");
        if (deviceId != null) {
            args.add("-s");
            args.add(deviceId);
        }
        args.add("shell");
        args.add("monkey");
        args.add("-p");
        args.add(packageName);
        args.add("-c");
        args.add("android.intent.category.LAUNCHER");
        args.add("1");

        GeneralCommandLine cmd = new GeneralCommandLine(args);
        consolePanel.info("[ZAFrida] Open app command: " + cmd.getCommandLineString());

        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                CapturingProcessHandler handler = new CapturingProcessHandler(cmd);
                ProcessOutput out = handler.runProcess(10_000);
                String stdout = out.getStdout() != null ? out.getStdout().trim() : "";
                String stderr = out.getStderr() != null ? out.getStderr().trim() : "";
                int exitCode = out.getExitCode();
                ApplicationManager.getApplication().invokeLater(() -> {
                    if (exitCode == 0) {
                        consolePanel.info("[ZAFrida] Opened app: " + packageName);
                        if (!stdout.isBlank()) {
                            consolePanel.info(stdout);
                        }
                    } else {
                        String detail = !stderr.isBlank() ? stderr : stdout;
                        if (detail.isBlank()) detail = "unknown error";
                        consolePanel.error("[ZAFrida] Open app failed (exit=" + exitCode + "): " + detail);
                    }
                });
            } catch (Throwable t) {
                ApplicationManager.getApplication().invokeLater(() ->
                        consolePanel.error("[ZAFrida] Open app failed: " + t.getMessage())
                );
            }
        });
    }

    private @Nullable String resolveForceStopPackage(@Nullable ZaFridaProjectConfig cfg) {
        boolean gadgetMode = cfg != null && cfg.connectionMode == FridaConnectionMode.GADGET;
        String target = gadgetMode ? "" : (targetField.getText() != null ? targetField.getText().trim() : "");
        if (!target.isEmpty()) {
            if (!isNumeric(target)) return target;
        }
        if (cfg != null && !StringUtil.isEmptyOrSpaces(cfg.lastTarget)) {
            return cfg.lastTarget.trim();
        }
        return null;
    }

    private static boolean isNumeric(@NotNull String value) {
        for (int i = 0; i < value.length(); i++) {
            if (!Character.isDigit(value.charAt(i))) return false;
        }
        return !value.isEmpty();
    }

    private void setRunningState(boolean running) {
        runBtn.setEnabled(!running);
        attachBtn.setEnabled(!running);
        stopBtn.setEnabled(running);
        syncExternalRunStopButtons();
    }

    private void syncExternalRunStopButtons() {
        if (externalRunBtn != null) {
            externalRunBtn.setEnabled(runBtn.isEnabled());
        }
        if (externalStopBtn != null) {
            externalStopBtn.setEnabled(stopBtn.isEnabled());
        }
    }

    private void disableControls(boolean disabled) {
        deviceCombo.setEnabled(!disabled);
        refreshDevicesBtn.setEnabled(!disabled);
        addRemoteBtn.setEnabled(!disabled);
    }


    @Override
    public void dispose() {
        // project service handles stop
    }
}
