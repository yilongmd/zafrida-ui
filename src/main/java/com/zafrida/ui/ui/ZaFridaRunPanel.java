package com.zafrida.ui.ui;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.fileChooser.FileChooser;
import com.intellij.openapi.fileChooser.FileChooserDescriptor;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.ComboBox;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.util.IconLoader;
import com.intellij.icons.AllIcons;
import com.intellij.openapi.vfs.VirtualFile;
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
import com.zafrida.ui.ui.render.DeviceCellRenderer;
import com.zafrida.ui.util.ProjectFileUtil;
import com.zafrida.ui.util.ZaFridaNotifier;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.settings.ZaFridaSettingsState;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import com.intellij.openapi.util.text.StringUtil;

public final class ZaFridaRunPanel extends JPanel implements Disposable {

    private final @NotNull Project project;
    private final @NotNull ZaFridaConsolePanel consolePanel;
    private final @NotNull ZaFridaTemplatePanel templatePanel;

    private final @NotNull FridaCliService fridaCli;
    private final @NotNull ZaFridaSessionService sessionService;

    private final ComboBox<FridaDevice> deviceCombo = new ComboBox<>();
    private final JButton refreshDevicesBtn = new JButton("Refresh");
    private final JButton addRemoteBtn = new JButton("+Remote");

    private final JBTextField scriptField = new JBTextField();
    private final JButton chooseScriptBtn = new JButton("Choose...");

    private final JRadioButton spawnRadio = new JRadioButton("Spawn (-f)", true);
    private final JRadioButton attachRadio = new JRadioButton("Attach (-p)");
    private final JBTextField targetField = new JBTextField();

    private final JCheckBox noPauseCheck = new JCheckBox("--no-pause", true);
    private final JBTextField extraArgsField = new JBTextField();

    private final JButton runBtn = new JButton("Run");
    private final JButton stopBtn = new JButton("Stop");
    private final JButton clearConsoleBtn = new JButton("Clear Console");

    private final JLabel logFileLabel = new JLabel("Log: (not started)");

    private @Nullable VirtualFile scriptFile;

    private boolean printedToolchainInfo = false;

    private final ZaFridaProjectManager fridaProjectManager;
    private final SearchableComboBoxPanel<ZaFridaFridaProject> fridaProjectSelector =
            new SearchableComboBoxPanel<>(p -> p == null ? "" : p.getName());
    private final JButton newFridaProjectBtn = new JButton("New Project");
    private final JButton projectSettingsBtn = new JButton("Settings");
    private final JButton languageToggleBtn =
            new JButton(IconLoader.getIcon("/META-INF/icons/lang-toggle.svg", ZaFridaRunPanel.class));
    private boolean updatingFridaProjectSelector = false;


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
        row = addRow(form, row, new JLabel("Script"), buildScriptRow());
        row = addRow(form, row, new JLabel("Mode"), buildModeRow());
        row = addRow(form, row, new JLabel("Extra"), buildExtraRow());
        row = addRow(form, row, new JLabel(""), buildButtonsRow());

        JPanel top = new JPanel(new BorderLayout());
        top.add(buildTopActionRow(), BorderLayout.NORTH);
        top.add(form, BorderLayout.CENTER);
        add(top, BorderLayout.NORTH);
        add(logFileLabel, BorderLayout.SOUTH);

        initUiState();
        bindActions();
        subscribeToFridaProjectChanges();
        reloadFridaProjectsIntoUi();
        applyActiveFridaProjectToUi(fridaProjectManager.getActiveProject());
        reloadDevicesAsync();
    }

    private void initUiState() {
        deviceCombo.setRenderer(new DeviceCellRenderer());
        scriptField.setEditable(false);
        stopBtn.setEnabled(false);
        extraArgsField.setToolTipText("Extra args passed to frida, e.g. --realm=emulated");

        ButtonGroup group = new ButtonGroup();
        group.add(spawnRadio);
        group.add(attachRadio);

        targetField.setColumns(18);
        extraArgsField.setColumns(18);
        languageToggleBtn.setToolTipText("中文 / English");

        refreshDevicesBtn.setIcon(AllIcons.Actions.Refresh);
        addRemoteBtn.setIcon(AllIcons.General.Add);
        chooseScriptBtn.setIcon(AllIcons.Actions.MenuOpen);
        runBtn.setIcon(AllIcons.Actions.Execute);
        stopBtn.setIcon(AllIcons.Actions.Suspend);
        clearConsoleBtn.setIcon(AllIcons.Actions.ClearCash);
        newFridaProjectBtn.setIcon(AllIcons.Actions.NewFolder);
        projectSettingsBtn.setIcon(AllIcons.General.Settings);
    }

    private JPanel buildFridaProjectRow() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        row.add(fridaProjectSelector);
        return row;
    }

    private JPanel buildTopActionRow() {
        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        row.add(newFridaProjectBtn);
        row.add(projectSettingsBtn);
        row.add(languageToggleBtn);
        return row;
    }

    private void bindActions() {
        refreshDevicesBtn.addActionListener(e -> reloadDevicesAsync());

        addRemoteBtn.addActionListener(e -> {
            String host = Messages.showInputDialog(this, "host:port", "Add Frida Remote Host", null);
            if (host == null) return;
            String h = host.trim();
            if (h.isEmpty()) return;
            ApplicationManager.getApplication().getService(ZaFridaSettingsService.class).addRemoteHost(h);
            reloadDevicesAsync();
        });

        clearConsoleBtn.addActionListener(e -> consolePanel.clear());

        runBtn.addActionListener(e -> runFrida());
        stopBtn.addActionListener(e -> stopFrida());

        fridaProjectSelector.addActionListener(e -> {
            if (updatingFridaProjectSelector) return;
            fridaProjectManager.setActiveProject(fridaProjectSelector.getSelectedItem());
        });
        newFridaProjectBtn.addActionListener(e -> createNewFridaProject());
        projectSettingsBtn.addActionListener(e -> openProjectSettings());
        languageToggleBtn.addActionListener(e -> Messages.showInfoMessage(
                project,
                "Switch UI language (中文/English) is coming soon.",
                "ZAFrida"
        ));
        chooseScriptBtn.addActionListener(e -> {
            ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
            VirtualFile initial = active != null ? fridaProjectManager.resolveProjectDir(active) : null;

            VirtualFile file = null;
            if (initial != null) {
                FileChooserDescriptor d = new FileChooserDescriptor(true, false, false, false, false, false);
                d.withFileFilter(vf -> "js".equalsIgnoreCase(vf.getExtension()));
                file = FileChooser.chooseFile(d, project, initial);
            }
            if (file == null) file = ProjectFileUtil.chooseJavaScriptFile(project);
            if (file == null) return;

            setScriptFile(file);

            if (active != null) {
                String rel = fridaProjectManager.toProjectRelativePath(active, file);
                if (rel != null) fridaProjectManager.updateProjectConfig(active, c -> c.mainScript = rel);
            }
        });

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
            newFridaProjectBtn.setEnabled(true);

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

        templatePanel.setCurrentPlatform(active == null ? null : active.getPlatform());

        if (active == null) {
            // 不强制清空，让用户仍可用“自由脚本模式”
            return;
        }

        ZaFridaProjectConfig cfg = fridaProjectManager.loadProjectConfig(active);

        // 1) 恢复 lastTarget（由设置页保存）
        if (!StringUtil.isEmptyOrSpaces(cfg.lastTarget)) {
            targetField.setText(cfg.lastTarget);
        }

        // 2) 恢复 mainScript（项目内相对路径）
        VirtualFile dir = fridaProjectManager.resolveProjectDir(active);
        if (dir != null) {
            String rel = cfg.mainScript;
            if (!StringUtil.isEmptyOrSpaces(rel)) {
                VirtualFile f = dir.findFileByRelativePath(rel);
                if (f != null && !f.isDirectory()) {
                    setScriptFile(f);
                } else {
                    // mainScript 丢失时给个提示，不强制创建，避免误操作
                    consolePanel.warn("[ZAFrida] Main script not found in project: " + rel);
                }
            }
        }
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
                () -> (FridaDevice) deviceCombo.getSelectedItem()
        );
        if (dialog.showAndGet()) {
            applyActiveFridaProjectToUi(fridaProjectManager.getActiveProject());
        }
    }






    private JPanel buildDeviceRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        deviceCombo.setPrototypeDisplayValue(new FridaDevice("usb", "usb", "Android"));
        p.add(deviceCombo);
        p.add(refreshDevicesBtn);
        p.add(addRemoteBtn);
        return p;
    }


    private JPanel buildScriptRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        scriptField.setColumns(22);
        p.add(scriptField);
        p.add(chooseScriptBtn);
        return p;
    }

    private JPanel buildModeRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        p.add(spawnRadio);
        p.add(attachRadio);
        p.add(new JLabel("Target:"));
        p.add(targetField);
        return p;
    }

    private JPanel buildExtraRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        p.add(noPauseCheck);
        p.add(new JLabel("Args:"));
        p.add(extraArgsField);
        return p;
    }

    private JPanel buildButtonsRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        p.add(runBtn);
        p.add(stopBtn);
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

    private void setScriptFile(@NotNull VirtualFile file) {
        this.scriptFile = file;
        this.scriptField.setText(file.getPath());
        this.templatePanel.setCurrentScriptFile(file);
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

        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                List<FridaDevice> devices = new ArrayList<>(fridaCli.listDevices(project));
                // add remotes from settings
                var remotes = ApplicationManager.getApplication()
                        .getService(ZaFridaSettingsService.class)
                        .getRemoteHosts();
                for (String host : remotes) {
                    devices.add(new FridaDevice("remote:" + host, "remote", "Remote", FridaDeviceMode.HOST, host));
                }

                ApplicationManager.getApplication().invokeLater(() -> {
                    deviceCombo.removeAllItems();
                    for (FridaDevice d : devices) deviceCombo.addItem(d);
                    if (!devices.isEmpty()) deviceCombo.setSelectedIndex(0);
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


    private void runFrida() {
        FridaDevice dev = (FridaDevice) deviceCombo.getSelectedItem();
        if (dev == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "No device selected");
            return;
        }

        // 1) 先统一拿到 target（spawn=包名/进程名，attach=pid 字符串）
        String target = targetField.getText() != null ? targetField.getText().trim() : "";
        if (target.isEmpty()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Target is empty");
            return;
        }

        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();

        // 2) 脚本选择优先级：
        //    a) 用户手动选过的 scriptFile
        //    b) templatePanel 当前脚本
        //    c) active 项目配置里的 mainScript
        //    d) spawn 模式：根据 target 自动生成默认主脚本
        VirtualFile script = scriptFile != null ? scriptFile : templatePanel.getCurrentScriptFile();

        if (script == null && active != null) {
            ZaFridaProjectConfig pc = fridaProjectManager.loadProjectConfig(active);
            VirtualFile dir = fridaProjectManager.resolveProjectDir(active);
            if (dir != null && pc != null && !StringUtil.isEmptyOrSpaces(pc.mainScript)) {
                VirtualFile cand = dir.findFileByRelativePath(pc.mainScript);
                if (cand != null && !cand.isDirectory()) {
                    setScriptFile(cand);
                    script = cand;
                }
            }
        }

        if (script == null && active != null && spawnRadio.isSelected()) {
            VirtualFile auto = fridaProjectManager.ensureMainScriptForTarget(active, target);
            setScriptFile(auto);
            script = auto;
        }

        if (script == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Choose a script file first");
            return;
        }

        // 3) 持久化配置：lastTarget / mainScript
        if (active != null && spawnRadio.isSelected()) {
            fridaProjectManager.updateProjectConfig(active, c -> c.lastTarget = target);
        }
        if (active != null) {
            String rel = fridaProjectManager.toProjectRelativePath(active, script);
            if (rel != null) {
                fridaProjectManager.updateProjectConfig(active, c -> c.mainScript = rel);
            }
        }

        // 4) 构建 RunMode
        FridaRunMode mode;
        if (spawnRadio.isSelected()) {
            mode = new SpawnRunMode(target);
        } else {
            try {
                mode = new AttachPidRunMode(Integer.parseInt(target));
            } catch (NumberFormatException e) {
                ZaFridaNotifier.warn(project, "ZAFrida", "Attach mode requires PID integer");
                return;
            }
        }

        FridaRunConfig cfg = new FridaRunConfig(
                dev,
                mode,
                script.getPath(),
                noPauseCheck.isSelected(),
                extraArgsField.getText() != null ? extraArgsField.getText() : ""
        );

        try {
            RunningSession session = sessionService.start(
                    cfg,
                    consolePanel.getConsoleView(),
                    consolePanel::info,
                    consolePanel::error
            );

            session.getProcessHandler().addProcessListener(sessionService.createUiStateListener(() -> {
                runBtn.setEnabled(true);
                stopBtn.setEnabled(false);
            }));

            runBtn.setEnabled(false);
            stopBtn.setEnabled(true);
            logFileLabel.setText("Log: " + session.getLogFilePath());
            consolePanel.info("[ZAFrida] Log file: " + session.getLogFilePath());
        } catch (Throwable t) {
            consolePanel.error("[ZAFrida] Start failed: " + t.getMessage());
            ZaFridaNotifier.error(project, "ZAFrida", "Start failed: " + t.getMessage());
        }
    }


    private void stopFrida() {
        sessionService.stop();
        runBtn.setEnabled(true);
        stopBtn.setEnabled(false);
        consolePanel.info("[ZAFrida] Stopped");
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
