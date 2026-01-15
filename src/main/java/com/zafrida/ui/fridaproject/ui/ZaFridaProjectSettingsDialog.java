package com.zafrida.ui.fridaproject.ui;

import com.intellij.icons.AllIcons;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.application.ModalityState;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.ComboBox;
import com.intellij.openapi.ui.DialogWrapper;
import com.intellij.openapi.ui.Messages;
import com.zafrida.ui.frida.FridaCliService;
import com.zafrida.ui.frida.FridaConnectionMode;
import com.zafrida.ui.frida.FridaDevice;
import com.zafrida.ui.frida.FridaDeviceMode;
import com.zafrida.ui.frida.FridaProcess;
import com.zafrida.ui.frida.FridaProcessScope;
import com.zafrida.ui.fridaproject.ZaFridaFridaProject;
import com.zafrida.ui.fridaproject.ZaFridaProjectConfig;
import com.zafrida.ui.fridaproject.ZaFridaProjectManager;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.settings.ZaFridaSettingsState;
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
import java.util.function.Consumer;
import java.util.function.Supplier;
import com.intellij.ui.components.JBTextField;
/**
 * [UI组件] 项目详细配置对话框。
 * <p>
 * <strong>功能：</strong>
 * 编辑当前激活项目的 {@link ZaFridaProjectConfig}，包括连接模式、远程主机、目标包名等。
 * <p>
 * <strong>技术难点：</strong>
 * 包含“从设备刷新进程列表”的功能。该操作涉及耗时的 Frida CLI 调用，因此必须在后台线程执行，
 * 并通过 {@link com.intellij.openapi.application.ModalityState} 确保 UI 更新在正确的模态上下文中进行。
 */
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

    private @Nullable ZaFridaFridaProject activeProject;

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
        scopeCombo.addActionListener(e -> {
            if (selectTargetRadio.isSelected()) refreshTargets();
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
            return;
        }

        ZaFridaProjectConfig cfg = projectManager.loadProjectConfig(activeProject);
        connectionModeCombo.setEnabled(true);
        manualTargetRadio.setEnabled(true);
        selectTargetRadio.setEnabled(true);
        scopeCombo.setSelectedItem(cfg.processScope);
        setTargetText(cfg.lastTarget);
        connectionModeCombo.setSelectedItem(cfg.connectionMode != null ? cfg.connectionMode : FridaConnectionMode.USB);

        ZaFridaSettingsState st = ApplicationManager.getApplication()
                .getService(ZaFridaSettingsService.class)
                .getState();
        String host = !isBlank(cfg.remoteHost) ? cfg.remoteHost : safeHost(st.defaultRemoteHost);
        if (host.isEmpty()) host = "127.0.0.1";
        int port = cfg.remotePort > 0 ? cfg.remotePort : safePort(st.defaultRemotePort);
        remoteHostField.setText(host);
        remotePortField.setText(String.valueOf(port));

        manualTargetRadio.setSelected(cfg.targetManual);
        selectTargetRadio.setSelected(!cfg.targetManual);

        updateConnectionUi();
        updateTargetModeUi();
        if (selectTargetRadio.isSelected()) {
            refreshTargets();
        }
    }

    private void refreshTargets() {
        if (!selectTargetRadio.isSelected()) return;
        FridaDevice device = resolveDeviceForTargets();
        if (device == null) {
            Messages.showWarningDialog(project, "Select a device first in the Run panel.", "ZAFrida");
            logError("[ZAFrida] Select a device first in the Run panel.");
            return;
        }
        FridaProcessScope scope = (FridaProcessScope) scopeCombo.getSelectedItem();
        if (scope == null) scope = FridaProcessScope.RUNNING_APPS;

        // 该对话框是 Modal 的：如果直接 invokeLater（默认 NON_MODAL），更新 UI 的 Runnable 会被阻塞，
        // 进而出现 processes 明明有数据但 targetCombo 不刷新的现象。
        final ModalityState modality = ModalityState.stateForComponent(targetCombo);

        refreshTargetsBtn.setEnabled(false);
        FridaProcessScope finalScope = scope;
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                List<FridaProcess> processes = fridaCliService.listProcesses(project, device, finalScope);
                ApplicationManager.getApplication().invokeLater(() -> {
                    targetCombo.removeAllItems();
                    for (FridaProcess p : processes) {
                        String label = targetLabel(p);
                        if (label != null && !label.isBlank()) {
                            targetCombo.addItem(label);
                        }
                    }
                    refreshTargetsBtn.setEnabled(true);
                }, modality);
            } catch (Throwable t) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    refreshTargetsBtn.setEnabled(true);
                    logError("[ZAFrida] Load targets failed: " + t.getMessage());
                    Messages.showWarningDialog(project, "Load targets failed: " + t.getMessage(), "ZAFrida");
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
        FridaProcessScope scope = (FridaProcessScope) scopeCombo.getSelectedItem();
        String target = getTargetText();
        FridaConnectionMode connectionMode = (FridaConnectionMode) connectionModeCombo.getSelectedItem();
        HostPort hostPort = resolveHostPortForSave();

        projectManager.updateProjectConfig(activeProject, cfg -> {
            cfg.processScope = scope != null ? scope : FridaProcessScope.RUNNING_APPS;
            cfg.lastTarget = target.isEmpty() ? null : target;
            cfg.targetManual = manualTargetRadio.isSelected();
            cfg.connectionMode = connectionMode != null ? connectionMode : FridaConnectionMode.USB;
            cfg.remoteHost = hostPort.host;
            cfg.remotePort = hostPort.port;
        });
        super.doOKAction();
    }

    private String getTargetText() {
        if (manualTargetRadio.isSelected()) {
            return manualTargetField.getText() != null ? manualTargetField.getText().trim() : "";
        }
        Object selected = targetCombo.getSelectedItem();
        return selected != null ? selected.toString().trim() : "";
    }

    private void setTargetText(@Nullable String value) {
        manualTargetField.setText(value == null ? "" : value.trim());
        if (value == null || value.isBlank()) {
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
            String host = hostPort.host + ":" + hostPort.port;
            String type = mode == FridaConnectionMode.GADGET ? "gadget" : "remote";
            String name = mode == FridaConnectionMode.GADGET ? "Gadget" : "Remote";
            return new FridaDevice(type + ":" + host, type, name, FridaDeviceMode.HOST, host);
        }

        FridaDevice device = deviceSupplier.get();
        if (device != null) return device;

        if (activeProject != null) {
            ZaFridaProjectConfig cfg = projectManager.loadProjectConfig(activeProject);
            if (!isBlank(cfg.lastDeviceHost)) {
                return new FridaDevice("remote:" + cfg.lastDeviceHost, "remote", "Remote", FridaDeviceMode.HOST, cfg.lastDeviceHost);
            }
            if (!isBlank(cfg.lastDeviceId)) {
                return new FridaDevice(cfg.lastDeviceId, "device", cfg.lastDeviceId, FridaDeviceMode.DEVICE_ID, null);
            }
        }
        return null;
    }

    private HostPort resolveHostPortForSave() {
        ZaFridaSettingsState st = ApplicationManager.getApplication()
                .getService(ZaFridaSettingsService.class)
                .getState();
        String host = safeHost(remoteHostField.getText());
        if (host.isEmpty()) host = safeHost(st.defaultRemoteHost);
        if (host.isEmpty()) host = "127.0.0.1";

        int port = parsePort(remotePortField.getText());
        if (port <= 0) port = safePort(st.defaultRemotePort);
        return new HostPort(host, port);
    }

    private static boolean isBlank(@Nullable String value) {
        return value == null || value.trim().isEmpty();
    }

    private static String safeHost(@Nullable String host) {
        if (host == null) return "";
        return host.trim();
    }

    private static int safePort(int port) {
        return port > 0 ? port : 14725;
    }

    private static int parsePort(@Nullable String portText) {
        if (portText == null || portText.trim().isEmpty()) return 0;
        try {
            return Integer.parseInt(portText.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
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
        if (p.getIdentifier() != null && !p.getIdentifier().isBlank()) {
            return p.getIdentifier();
        }
        if (p.getName() != null && !p.getName().isBlank()) {
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
