package com.zafrida.ui.ui;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.ComboBox;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.ui.components.JBTextField;
import com.zafrida.ui.frida.*;
import com.zafrida.ui.session.RunningSession;
import com.zafrida.ui.session.ZaFridaSessionService;
import com.zafrida.ui.python.ProjectPythonEnvResolver;
import com.zafrida.ui.python.PythonEnvInfo;
import com.zafrida.ui.ui.render.DeviceCellRenderer;
import com.zafrida.ui.ui.render.ProcessCellRenderer;
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
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public final class ZaFridaRunPanel extends JPanel implements Disposable {

    private final @NotNull Project project;
    private final @NotNull ZaFridaConsolePanel consolePanel;
    private final @NotNull ZaFridaTemplatePanel templatePanel;

    private final @NotNull FridaCliService fridaCli;
    private final @NotNull ZaFridaSessionService sessionService;

    private final ComboBox<FridaDevice> deviceCombo = new ComboBox<>();
    private final JButton refreshDevicesBtn = new JButton("Refresh");
    private final JButton addRemoteBtn = new JButton("+Remote");

    private final ComboBox<FridaProcessScope> scopeCombo = new ComboBox<>(FridaProcessScope.values());
    private final ComboBox<FridaProcess> processCombo = new ComboBox<>();
    private final JButton refreshProcessesBtn = new JButton("Refresh");

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

    public ZaFridaRunPanel(@NotNull Project project,
                           @NotNull ZaFridaConsolePanel consolePanel,
                           @NotNull ZaFridaTemplatePanel templatePanel) {
        super(new BorderLayout());
        this.project = project;
        this.consolePanel = consolePanel;
        this.templatePanel = templatePanel;

        this.fridaCli = ApplicationManager.getApplication().getService(FridaCliService.class);
        this.sessionService = project.getService(ZaFridaSessionService.class);

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 8, 6, 8);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;

        int row = 0;
        row = addRow(form, row, new JLabel("Device"), buildDeviceRow());
        row = addRow(form, row, new JLabel("Scope"), buildProcessRow());
        row = addRow(form, row, new JLabel("Script"), buildScriptRow());
        row = addRow(form, row, new JLabel("Mode"), buildModeRow());
        row = addRow(form, row, new JLabel("Extra"), buildExtraRow());
        row = addRow(form, row, new JLabel(""), buildButtonsRow());

        add(form, BorderLayout.NORTH);
        add(logFileLabel, BorderLayout.SOUTH);

        initUiState();
        bindActions();
        reloadDevicesAsync();
    }

    private void initUiState() {
        deviceCombo.setRenderer(new DeviceCellRenderer());
        processCombo.setRenderer(new ProcessCellRenderer());
        scriptField.setEditable(false);
        stopBtn.setEnabled(false);
        extraArgsField.setToolTipText("Extra args passed to frida, e.g. --realm=emulated");

        ButtonGroup group = new ButtonGroup();
        group.add(spawnRadio);
        group.add(attachRadio);

        scopeCombo.setSelectedItem(FridaProcessScope.RUNNING_APPS);
        targetField.setColumns(28);
        extraArgsField.setColumns(28);
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
        refreshProcessesBtn.addActionListener(e -> reloadProcessesAsync());

        deviceCombo.addActionListener(e -> reloadProcessesAsync());
        scopeCombo.addActionListener(e -> reloadProcessesAsync());

        processCombo.addActionListener(e -> onProcessSelected());
        spawnRadio.addActionListener(e -> onProcessSelected());
        attachRadio.addActionListener(e -> onProcessSelected());

        chooseScriptBtn.addActionListener(e -> {
            VirtualFile file = ProjectFileUtil.chooseJavaScriptFile(project);
            if (file != null) {
                setScriptFile(file);
            }
        });

        clearConsoleBtn.addActionListener(e -> consolePanel.clear());

        runBtn.addActionListener(e -> runFrida());
        stopBtn.addActionListener(e -> stopFrida());
    }

    private JPanel buildDeviceRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        deviceCombo.setPrototypeDisplayValue(new FridaDevice("usb", "usb", "Android"));
        p.add(deviceCombo);
        p.add(refreshDevicesBtn);
        p.add(addRemoteBtn);
        return p;
    }

    private JPanel buildProcessRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        p.add(scopeCombo);
        processCombo.setPrototypeDisplayValue(new FridaProcess(1234, "com.example.app", "com.example.app"));
        p.add(processCombo);
        p.add(refreshProcessesBtn);
        return p;
    }

    private JPanel buildScriptRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        scriptField.setColumns(32);
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

    private void onProcessSelected() {
        FridaProcess p = (FridaProcess) processCombo.getSelectedItem();
        if (p == null) return;

        if (spawnRadio.isSelected()) {
            String t = p.getIdentifier();
            if (t == null || t.isBlank()) t = p.getName();
            targetField.setText(t);
        } else {
            Integer pid = p.getPid();
            targetField.setText(pid != null ? String.valueOf(pid) : "");
        }
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
                    reloadProcessesAsync();
                });
            } catch (Throwable t) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    consolePanel.error("[ZAFrida] Load devices failed: " + t.getMessage());
                    disableControls(false);
                });
            }
        });
    }

    private void reloadProcessesAsync() {
        FridaDevice dev = (FridaDevice) deviceCombo.getSelectedItem();
        if (dev == null) return;

        disableProcesses(true);
        consolePanel.info("[ZAFrida] Loading targets...");

        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                FridaProcessScope scope = (FridaProcessScope) scopeCombo.getSelectedItem();
                if (scope == null) scope = FridaProcessScope.RUNNING_APPS;

                List<FridaProcess> ps = fridaCli.listProcesses(project, dev, scope);

                ApplicationManager.getApplication().invokeLater(() -> {
                    processCombo.removeAllItems();
                    for (FridaProcess p : ps) processCombo.addItem(p);
                    if (!ps.isEmpty()) processCombo.setSelectedIndex(0);
                    consolePanel.info("[ZAFrida] Targets loaded: " + ps.size());
                    disableProcesses(false);
                    onProcessSelected();
                });
            } catch (Throwable t) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    consolePanel.error("[ZAFrida] Load targets failed: " + t.getMessage());
                    disableProcesses(false);
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
        VirtualFile script = scriptFile != null ? scriptFile : templatePanel.getCurrentScriptFile();
        if (script == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Choose a script file first");
            return;
        }

        String target = targetField.getText() != null ? targetField.getText().trim() : "";
        if (target.isEmpty()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Target is empty");
            return;
        }

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
        scopeCombo.setEnabled(!disabled);
        processCombo.setEnabled(!disabled);
        refreshProcessesBtn.setEnabled(!disabled);
    }

    private void disableProcesses(boolean disabled) {
        scopeCombo.setEnabled(!disabled);
        processCombo.setEnabled(!disabled);
        refreshProcessesBtn.setEnabled(!disabled);
    }

    @Override
    public void dispose() {
        // project service handles stop
    }
}
