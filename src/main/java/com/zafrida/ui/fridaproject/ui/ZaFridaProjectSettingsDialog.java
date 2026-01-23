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
import com.zafrida.ui.util.ZaFridaIcons;
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

    /** IDE 项目实例 */
    private final Project project;
    /** 项目管理器 */
    private final ZaFridaProjectManager projectManager;
    /** Frida CLI 服务 */
    private final FridaCliService fridaCliService;
    /** 设备提供器 */
    private final Supplier<FridaDevice> deviceSupplier;
    /** 错误日志回调 */
    private final @Nullable Consumer<String> errorLogger;

    /** 目标模式单选组 */
    private final ButtonGroup targetGroup = new ButtonGroup();

    /** 连接模式下拉框 */
    private final ComboBox<FridaConnectionMode> connectionModeCombo = new ComboBox<>(FridaConnectionMode.values());
    /** 远程主机输入框 */
    private final JBTextField remoteHostField = new JBTextField();
    /** 远程端口输入框 */
    private final JBTextField remotePortField = new JBTextField();

    /** 手动目标单选按钮 */
    private final JRadioButton manualTargetRadio = new JRadioButton("Manual");
    /** 设备选择目标单选按钮 */
    private final JRadioButton selectTargetRadio = new JRadioButton("Select from device");
    /** 手动目标输入框 */
    private final JBTextField manualTargetField = new JBTextField();

    /** 进程范围下拉框 */
    private final ComboBox<FridaProcessScope> scopeCombo = new ComboBox<>(FridaProcessScope.values());
    /** 目标选择下拉框 */
    private final ComboBox<String> targetCombo = new ComboBox<>();
    /** 目标刷新按钮 */
    private final JButton refreshTargetsBtn = new JButton("Refresh");

    /** 项目信息展示标签 */
    private final JLabel projectInfoLabel = new JLabel();

    /** 当前激活项目 */
    private @Nullable ZaFridaFridaProject activeProject;

    /**
     * 构造函数。
     * @param project 当前 IDE 项目
     * @param projectManager 项目管理器
     * @param fridaCliService Frida CLI 服务
     * @param deviceSupplier 设备提供器
     * @param errorLogger 错误日志回调（可为空）
     */
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

    /**
     * 创建对话框中心面板。
     * @return 中心面板组件
     */
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

    /**
     * 构建目标选择区域面板。
     * @return 面板
     */
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

    /**
     * 构建设备目标选择行。
     * @return 面板
     */
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

    /**
     * 构建远程主机输入行。
     * @return 面板
     */
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

    /**
     * 绑定 UI 事件。
     */
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

    /**
     * 从当前激活项目加载配置。
     */
    private void loadFromProject() {
        activeProject = projectManager.getActiveProject();
        updateProjectInfo();
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

    /**
     * 刷新项目信息展示。
     */
    private void updateProjectInfo() {
        if (activeProject == null) {
            projectInfoLabel.setIcon(null);
            projectInfoLabel.setText("No active project");
            projectInfoLabel.setToolTipText("No active project");
            return;
        }
        projectInfoLabel.setIcon(ZaFridaIcons.forPlatform(activeProject.getPlatform()));
        projectInfoLabel.setText(activeProject.getName());
        projectInfoLabel.setToolTipText("Platform: " + activeProject.getPlatform().name());
    }

    /**
     * 从设备刷新目标列表。
     */
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

    /**
     * 保存配置并关闭对话框。
     */
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

    /**
     * 获取当前目标文本。
     * @return 目标文本
     */
    private String getTargetText() {
        if (manualTargetRadio.isSelected()) {
            return manualTargetField.getText() != null ? manualTargetField.getText().trim() : "";
        }
        Object selected = targetCombo.getSelectedItem();
        return selected != null ? selected.toString().trim() : "";
    }

    /**
     * 设置目标文本并同步到 UI。
     * @param value 目标文本
     */
    private void setTargetText(@Nullable String value) {
        manualTargetField.setText(value == null ? "" : value.trim());
        if (value == null || value.isBlank()) {
            targetCombo.setSelectedItem(null);
            return;
        }
        targetCombo.setSelectedItem(value);
    }

    /**
     * 根据目标选择模式更新 UI。
     */
    private void updateTargetModeUi() {
        boolean manual = !selectTargetRadio.isSelected();
        manualTargetField.setEnabled(manual);
        targetCombo.setEnabled(!manual);
        refreshTargetsBtn.setEnabled(!manual);
        scopeCombo.setEnabled(!manual);
    }

    /**
     * 根据连接模式更新 UI。
     */
    private void updateConnectionUi() {
        FridaConnectionMode mode = (FridaConnectionMode) connectionModeCombo.getSelectedItem();
        boolean remote = mode == FridaConnectionMode.REMOTE || mode == FridaConnectionMode.GADGET;
        remoteHostField.setEnabled(remote);
        remotePortField.setEnabled(remote);
    }

    /**
     * 解析用于刷新目标列表的设备信息。
     * @return 设备或 null
     */
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

    /**
     * 解析并标准化要保存的主机与端口。
     * @return 主机端口对象
     */
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

    /**
     * 判断字符串是否为空或仅空白。
     * @param value 输入字符串
     * @return true 表示为空
     */
    private static boolean isBlank(@Nullable String value) {
        return value == null || value.trim().isEmpty();
    }

    /**
     * 标准化主机地址字符串。
     * @param host 输入主机
     * @return 标准化结果
     */
    private static String safeHost(@Nullable String host) {
        if (host == null) return "";
        return host.trim();
    }

    /**
     * 标准化端口值。
     * @param port 输入端口
     * @return 合法端口或默认值
     */
    private static int safePort(int port) {
        return port > 0 ? port : 14725;
    }

    /**
     * 解析端口文本。
     * @param portText 端口文本
     * @return 端口值或 0
     */
    private static int parsePort(@Nullable String portText) {
        if (portText == null || portText.trim().isEmpty()) return 0;
        try {
            return Integer.parseInt(portText.trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    /**
     * 简单的 Host:Port 结构体。
     */
    private static final class HostPort {
        /** 主机地址 */
        private final String host;
        /** 端口号 */
        private final int port;

        /**
         * 构造函数。
         * @param host 主机地址
         * @param port 端口号
         */
        private HostPort(String host, int port) {
            this.host = host;
            this.port = port;
        }
    }

    /**
     * 生成目标下拉框显示文本。
     * @param p 进程信息
     * @return 显示文本或 null
     */
    private static @Nullable String targetLabel(@NotNull FridaProcess p) {
        if (p.getIdentifier() != null && !p.getIdentifier().isBlank()) {
            return p.getIdentifier();
        }
        if (p.getName() != null && !p.getName().isBlank()) {
            return p.getName();
        }
        return null;
    }

    /**
     * 输出错误日志。
     * @param message 日志内容
     */
    private void logError(@NotNull String message) {
        if (errorLogger != null) {
            errorLogger.accept(message);
        }
    }
}
