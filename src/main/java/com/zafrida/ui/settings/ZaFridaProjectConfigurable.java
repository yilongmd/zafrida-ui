package com.zafrida.ui.settings;

import com.intellij.icons.AllIcons;
import com.intellij.openapi.options.Configurable;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.ComboBox;
import com.intellij.openapi.ui.Messages;
import com.intellij.ui.JBColor;
import com.intellij.ui.components.*;
import com.intellij.util.ui.JBUI;
import com.intellij.util.ui.UIUtil;
import com.zafrida.ui.config.ZaFridaGlobalSettings;
import com.zafrida.ui.config.ZaFridaProjectSettings;
import com.zafrida.ui.config.ZaFridaProjectSettings.DeviceConnectionMode;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import java.awt.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
/**
 * [UI入口] 项目级 (Per-Project) 设置面板。
 * <p>
 * <strong>配置层级：</strong>
 * 存储在 {@code .idea/zafrida-project.xml} 中。
 * <p>
 * <strong>关键功能：</strong>
 * 1. 设置当前项目的目标包名 (Package Name)。
 * 2. 配置连接模式 (USB/Remote) 和特定于该项目的远程地址。
 * 3. <strong>特色功能：</strong> 支持直接从连接的设备中拉取已安装应用列表来填充包名选择框。
 */
public class ZaFridaProjectConfigurable implements Configurable {

    /** 项目 */
    private final @NotNull Project project;
    /** 项目设置实例 */
    private final @NotNull ZaFridaProjectSettings settings;
    /** 全局设置实例 */
    private final @NotNull ZaFridaGlobalSettings globalSettings;

    /** 插件主面板 */
    private JPanel mainPanel;
    /** 包名文本框 */
    private JBTextField packageNameField;
    /** 包名下拉框 */
    private ComboBox<String> packageComboBox;
    /** 刷新包名按钮 */
    private JButton refreshPackagesButton;
    /** 保存包名按钮 */
    private JButton savePackageButton;

    /** 设备连接模式下拉框 */
    private ComboBox<DeviceConnectionMode> connectionModeCombo;
    /** 远程主机文本框 */
    private JBTextField remoteHostField;
    /** 远程端口文本框 */
    private JBTextField remotePortField;
    /** 额外参数文本框 */
    private JBTextField additionalArgsField;
    /** Spawn 模式复选框 */
    private JBCheckBox spawnModeCheckBox;

    /** 命令预览标签 */
    private JBLabel commandPreviewLabel;

    public ZaFridaProjectConfigurable(@NotNull Project project) {
        this.project = project;
        this.settings = ZaFridaProjectSettings.getInstance(project);
        this.globalSettings = ZaFridaGlobalSettings.getInstance();
    }

    @Nls(capitalization = Nls.Capitalization.Title)
    @Override
    public String getDisplayName() {
        return "ZaFrida Project";
    }

    @Override
    public @Nullable JComponent createComponent() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(JBUI.Borders.empty(10));

        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));

        // === 包名配置 ===
        contentPanel.add(createSectionLabel("Package Configuration"));
        contentPanel.add(Box.createVerticalStrut(8));

        JPanel packagePanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = JBUI.insets(4);

        // 手动输入包名
        gbc.gridx = 0;
        gbc.gridy = 0;
        packagePanel.add(new JBLabel("Package Name:"), gbc);

        packageNameField = new JBTextField(30);
        packageNameField.getEmptyText().setText("com.example.app");
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        packagePanel.add(packageNameField, gbc);

        savePackageButton = new JButton("Save", AllIcons.Actions.MenuSaveall);
        savePackageButton.setToolTipText("Save package name to project settings");
        savePackageButton.addActionListener(e -> savePackageName());
        gbc.gridx = 2;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.NONE;
        packagePanel.add(savePackageButton, gbc);

        // 历史包名
        gbc.gridx = 0;
        gbc.gridy = 1;
        packagePanel.add(new JBLabel("Recent Packages:"), gbc);

        packageComboBox = new ComboBox<>(new DefaultComboBoxModel<>());
        packageComboBox.setEditable(false);
        packageComboBox.addActionListener(e -> {
            String selected = (String) packageComboBox.getSelectedItem();
            if (selected != null && !selected.isEmpty() && !selected.startsWith("--")) {
                packageNameField.setText(selected);
            }
        });
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        packagePanel.add(packageComboBox, gbc);

        // 从设备刷新包名
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 0;
        packagePanel.add(new JBLabel("Or refresh from device:"), gbc);

        JPanel refreshPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        refreshPackagesButton = new JButton("Refresh Packages", AllIcons.Actions.Refresh);
        refreshPackagesButton.setToolTipText("Get installed packages from connected device");
        refreshPackagesButton.addActionListener(e -> refreshPackagesFromDevice());
        refreshPanel.add(refreshPackagesButton);

        JBLabel hintLabel = new JBLabel("(requires USB device)");
        hintLabel.setForeground(JBUI.CurrentTheme.ContextHelp.FOREGROUND);
        refreshPanel.add(hintLabel);

        gbc.gridx = 1;
        gbc.gridwidth = 2;
        packagePanel.add(refreshPanel, gbc);

        contentPanel.add(packagePanel);
        contentPanel.add(Box.createVerticalStrut(16));

        // === 设备连接配置 ===
        contentPanel.add(createSectionLabel("Device Connection"));
        contentPanel.add(Box.createVerticalStrut(8));

        JPanel devicePanel = new JPanel(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = JBUI.insets(4);

        gbc.gridx = 0;
        gbc.gridy = 0;
        devicePanel.add(new JBLabel("Connection Mode:"), gbc);

        connectionModeCombo = new ComboBox<>(DeviceConnectionMode.values());
        connectionModeCombo.addActionListener(e -> {
            updateConnectionFields();
            updateCommandPreview();
        });
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        devicePanel.add(connectionModeCombo, gbc);

        // Remote Host
        // 远程主机
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.fill = GridBagConstraints.NONE;
        devicePanel.add(new JBLabel("Remote Host:Port:"), gbc);

        JPanel hostPortPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        remoteHostField = new JBTextField(15);
        remoteHostField.getEmptyText().setText("127.0.0.1");
        remoteHostField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateCommandPreview(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateCommandPreview(); }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateCommandPreview(); }
        });

        remotePortField = new JBTextField(6);
        remotePortField.getEmptyText().setText("14725");
        remotePortField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateCommandPreview(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateCommandPreview(); }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateCommandPreview(); }
        });

        hostPortPanel.add(remoteHostField);
        hostPortPanel.add(new JBLabel(":"));
        hostPortPanel.add(remotePortField);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        devicePanel.add(hostPortPanel, gbc);

        contentPanel.add(devicePanel);
        contentPanel.add(Box.createVerticalStrut(16));

        // === 运行配置 ===
        contentPanel.add(createSectionLabel("Run Configuration"));
        contentPanel.add(Box.createVerticalStrut(8));

        JPanel runPanel = new JPanel(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = JBUI.insets(4);

        gbc.gridx = 0;
        gbc.gridy = 0;
        runPanel.add(new JBLabel("Additional Args:"), gbc);

        additionalArgsField = new JBTextField(40);
        additionalArgsField.setToolTipText("Additional Frida command line arguments (e.g., --realm=native)");
        additionalArgsField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void changedUpdate(javax.swing.event.DocumentEvent e) { updateCommandPreview(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { updateCommandPreview(); }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { updateCommandPreview(); }
        });
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        runPanel.add(additionalArgsField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        spawnModeCheckBox = new JBCheckBox("Spawn mode (-f)");
        spawnModeCheckBox.setToolTipText("Use -f flag to spawn a new process (vs attach mode)");
        spawnModeCheckBox.addActionListener(e -> updateCommandPreview());
        runPanel.add(spawnModeCheckBox, gbc);

        contentPanel.add(runPanel);
        contentPanel.add(Box.createVerticalStrut(16));

        // === 命令预览 ===
        contentPanel.add(createSectionLabel("Command Preview"));
        contentPanel.add(Box.createVerticalStrut(8));

        commandPreviewLabel = new JBLabel();
        commandPreviewLabel.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        commandPreviewLabel.setForeground(JBUI.CurrentTheme.Label.disabledForeground());

        JPanel previewPanel = new JPanel(new BorderLayout());
        previewPanel.setBorder(JBUI.Borders.empty(8));
        // 使用正确的背景色 API
        previewPanel.setBackground(UIUtil.getPanelBackground());
        previewPanel.add(commandPreviewLabel, BorderLayout.CENTER);

        contentPanel.add(previewPanel);

        // Hints
        // 使用提示
        contentPanel.add(Box.createVerticalStrut(16));
        JBLabel hintLabel2 = new JBLabel(
                "<html><small style='color:gray'>" +
                        "• USB: frida -U -f com.example.app -l script.js<br>" +
                        "• Remote: frida -H 127.0.0.1:14725 -f com.example.app -l script.js<br>" +
                        "• Gadget: frida -H 127.0.0.1:14725 -F -l script.js" +
                        "</small></html>"
        );
        contentPanel.add(hintLabel2);

        mainPanel.add(new JBScrollPane(contentPanel), BorderLayout.CENTER);

        reset();
        return mainPanel;
    }

    private JBLabel createSectionLabel(String text) {
        JBLabel label = new JBLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 13f));
        return label;
    }

    private void updateConnectionFields() {
        DeviceConnectionMode mode = (DeviceConnectionMode) connectionModeCombo.getSelectedItem();
        boolean isRemote = mode == DeviceConnectionMode.REMOTE || mode == DeviceConnectionMode.GADGET;
        remoteHostField.setEnabled(isRemote);
        remotePortField.setEnabled(isRemote);
        spawnModeCheckBox.setEnabled(mode != DeviceConnectionMode.GADGET);
        packageNameField.setEnabled(mode != DeviceConnectionMode.GADGET);
        packageComboBox.setEnabled(mode != DeviceConnectionMode.GADGET);
        savePackageButton.setEnabled(mode != DeviceConnectionMode.GADGET);
        updateCommandPreview();
    }

    private void updateCommandPreview() {
        DeviceConnectionMode mode = (DeviceConnectionMode) connectionModeCombo.getSelectedItem();
        if (mode == null) return;

        StringBuilder cmd = new StringBuilder("frida ");

        switch (mode) {
            case USB:
                cmd.append("-U ");
                if (spawnModeCheckBox.isSelected()) {
                    String pkg = packageNameField.getText().trim();
                    cmd.append("-f ").append(pkg.isEmpty() ? "<package>" : pkg).append(" ");
                }
                break;

            case REMOTE:
                String host = remoteHostField.getText().trim();
                String port = remotePortField.getText().trim();
                cmd.append("-H ").append(host.isEmpty() ? "127.0.0.1" : host)
                        .append(":").append(port.isEmpty() ? "14725" : port).append(" ");
                if (spawnModeCheckBox.isSelected()) {
                    String pkg = packageNameField.getText().trim();
                    cmd.append("-f ").append(pkg.isEmpty() ? "<package>" : pkg).append(" ");
                }
                break;

            case GADGET:
                String gadgetHost = remoteHostField.getText().trim();
                String gadgetPort = remotePortField.getText().trim();
                cmd.append("-H ").append(gadgetHost.isEmpty() ? "127.0.0.1" : gadgetHost)
                        .append(":").append(gadgetPort.isEmpty() ? "14725" : gadgetPort).append(" ");
                cmd.append("-F ");
                break;
        }

        String args = additionalArgsField.getText().trim();
        if (!args.isEmpty()) {
            cmd.append(args).append(" ");
        }

        cmd.append("-l <script.js>");

        commandPreviewLabel.setText(cmd.toString());
    }

    private void savePackageName() {
        String pkg = packageNameField.getText().trim();
        if (!pkg.isEmpty()) {
            settings.packageName = pkg;
            settings.addRecentPackage(pkg);
            loadRecentPackages();
            Messages.showInfoMessage(project,
                    "Package name saved: " + pkg,
                    "ZaFrida");
        }
    }

    private void loadRecentPackages() {
        packageComboBox.removeAllItems();
        if (settings.recentPackages.isEmpty()) {
            packageComboBox.addItem("-- No recent packages --");
        } else {
            for (String pkg : settings.recentPackages) {
                packageComboBox.addItem(pkg);
            }
        }
    }

    private void refreshPackagesFromDevice() {
        refreshPackagesButton.setEnabled(false);
        refreshPackagesButton.setText("Refreshing...");

        new Thread(() -> {
            try {
                List<String> packages = getInstalledPackagesFromDevice();

                SwingUtilities.invokeLater(() -> {
                    packageComboBox.removeAllItems();
                    if (packages.isEmpty()) {
                        packageComboBox.addItem("-- No packages found --");
                        Messages.showWarningDialog(project,
                                "No packages found. Make sure a device is connected via USB.",
                                "ZaFrida");
                    } else {
                        for (String pkg : packages) {
                            packageComboBox.addItem(pkg);
                            settings.addRecentPackage(pkg);
                        }
                        Messages.showInfoMessage(project,
                                "Found " + packages.size() + " installed packages",
                                "ZaFrida");
                    }

                    refreshPackagesButton.setEnabled(true);
                    refreshPackagesButton.setText("Refresh Packages");
                });

            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    Messages.showErrorDialog(project,
                            "Failed to get packages: " + ex.getMessage() +
                                    "\n\nMake sure frida-ps is installed and device is connected.",
                            "ZaFrida Error");
                    refreshPackagesButton.setEnabled(true);
                    refreshPackagesButton.setText("Refresh Packages");
                });
            }
        }).start();
    }

    private List<String> getInstalledPackagesFromDevice() throws Exception {
        List<String> packages = new ArrayList<>();

        String fridaPsPath = globalSettings.fridaPsPath;
        if (fridaPsPath.isEmpty()) {
            fridaPsPath = "frida-ps";
        }

        ProcessBuilder pb = new ProcessBuilder(fridaPsPath, "-Uai");
        Process process = pb.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            boolean skipHeader = true;
            while ((line = reader.readLine()) != null) {
                if (skipHeader) {
                    skipHeader = false;
                    continue;
                }

                // frida-ps -Uai 输出格式: "PID  Name            Identifier"
                String[] parts = line.trim().split("\\s{2,}");
                if (parts.length >= 3) {
                    String identifier = parts[2].trim();
                    if (!identifier.isEmpty() && identifier.contains(".")) {
                        packages.add(identifier);
                    }
                }
            }
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("frida-ps exited with code " + exitCode);
        }

        return packages;
    }

    @Override
    public boolean isModified() {
        if (!packageNameField.getText().trim().equals(settings.packageName)) return true;
        if (connectionModeCombo.getSelectedItem() != settings.connectionMode) return true;
        if (!remoteHostField.getText().trim().equals(settings.remoteHost)) return true;
        if (!remotePortField.getText().trim().equals(String.valueOf(settings.remotePort))) return true;
        if (!additionalArgsField.getText().trim().equals(settings.additionalArgs)) return true;
        if (spawnModeCheckBox.isSelected() != settings.spawnMode) return true;
        return false;
    }

    @Override
    public void apply() {
        settings.packageName = packageNameField.getText().trim();
        settings.connectionMode = (DeviceConnectionMode) connectionModeCombo.getSelectedItem();
        settings.remoteHost = remoteHostField.getText().trim();

        if (settings.remoteHost.isEmpty()) {
            settings.remoteHost = globalSettings.defaultRemoteHost;
        }

        try {
            int port = Integer.parseInt(remotePortField.getText().trim());
            settings.remotePort = port;
        } catch (NumberFormatException e) {
            settings.remotePort = globalSettings.defaultRemotePort;
        }

        settings.additionalArgs = additionalArgsField.getText().trim();
        settings.spawnMode = spawnModeCheckBox.isSelected();
    }

    @Override
    public void reset() {
        packageNameField.setText(settings.packageName);
        connectionModeCombo.setSelectedItem(settings.connectionMode);

        String host = settings.remoteHost.isEmpty() ? globalSettings.defaultRemoteHost : settings.remoteHost;
        remoteHostField.setText(host);

        int port = settings.remotePort == 0 ? globalSettings.defaultRemotePort : settings.remotePort;
        remotePortField.setText(String.valueOf(port));

        additionalArgsField.setText(settings.additionalArgs);
        spawnModeCheckBox.setSelected(settings.spawnMode);

        loadRecentPackages();
        updateConnectionFields();
        updateCommandPreview();
    }
}
