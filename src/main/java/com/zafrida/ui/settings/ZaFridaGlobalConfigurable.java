package com.zafrida.ui.settings;

import com.intellij.openapi.fileChooser.FileChooserDescriptorFactory;
import com.intellij.openapi.options.Configurable;
import com.intellij.openapi.ui.TextBrowseFolderListener;
import com.intellij.openapi.ui.TextFieldWithBrowseButton;
import com.intellij.ui.components.JBCheckBox;
import com.intellij.ui.components.JBLabel;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.components.JBTextField;
import com.intellij.util.ui.JBUI;
import com.zafrida.ui.config.ZaFridaGlobalSettings;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import java.awt.*;
/**
 * [UI入口] (扩展) 全局高级设置面板。
 * <p>
 * <strong>职责：</strong>
 * 提供比基础设置更详细的配置项，如控制台缓冲区大小 (Max Console Lines)、字体大小、自动滚动等 UI 偏好设置。
 * 使用 {@link com.zafrida.ui.config.ZaFridaGlobalSettings} 进行数据存储。
 */
public class ZaFridaGlobalConfigurable implements Configurable {

    /** 全局设置实例 */
    private final ZaFridaGlobalSettings settings = ZaFridaGlobalSettings.getInstance();

    /** 根面板 */
    private JPanel mainPanel;
    /** frida 路径选择框 */
    private TextFieldWithBrowseButton fridaPathField;
    /** python 路径选择框 */
    private TextFieldWithBrowseButton pythonPathField;
    /** frida-ps 路径输入框 */
    private JBTextField fridaPsPathField;
    /** frida-ls-devices 路径输入框 */
    private JBTextField fridaLsDevicesPathField;

    /** 默认远程主机输入框 */
    private JBTextField defaultRemoteHostField;
    /** 默认远程端口输入框 */
    private JBTextField defaultRemotePortField;

    /** 控制台最大行数输入框 */
    private JBTextField maxConsoleLinesField;
    /** 控制台自动滚动复选框 */
    private JBCheckBox autoScrollConsoleCheckBox;
    /** 控制台字体大小输入框 */
    private JBTextField consoleFontSizeField;

    /** 自动同步模板复选框 */
    private JBCheckBox autoSyncTemplatesCheckBox;
    /** 显示快捷键提示复选框 */
    private JBCheckBox showKeyboardHintsCheckBox;
    /** 详细日志模式复选框 */
    private JBCheckBox verboseModeCheckBox;

    /** 自动刷新设备列表复选框 */
    private JBCheckBox autoRefreshDevicesCheckBox;
    /** 设备刷新间隔输入框 */
    private JBTextField refreshDeviceIntervalField;

    @Nls(capitalization = Nls.Capitalization.Title)
    /**
     * 设置页面显示名称。
     * @return 显示名称
     */
    @Override
    public String getDisplayName() {
        return "ZaFrida";
    }

    /**
     * 创建设置面板组件。
     * @return 面板组件
     */
    @Override
    public @Nullable JComponent createComponent() {
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(JBUI.Borders.empty(10));

        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));

        // === Frida 环境 ===
        contentPanel.add(createSectionLabel("Frida Environment"));
        contentPanel.add(Box.createVerticalStrut(8));

        JPanel envPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = JBUI.insets(4);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 0;
        envPanel.add(new JBLabel("Frida Path:"), gbc);

        fridaPathField = new TextFieldWithBrowseButton();
        fridaPathField.addActionListener(new TextBrowseFolderListener(
                FileChooserDescriptorFactory.createSingleFileDescriptor(),
                null
        ));
        fridaPathField.setToolTipText("Path to frida executable (leave empty to use system frida)");
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        envPanel.add(fridaPathField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0;
        envPanel.add(new JBLabel("Python Path:"), gbc);

        pythonPathField = new TextFieldWithBrowseButton();
        pythonPathField.addActionListener(new TextBrowseFolderListener(
                FileChooserDescriptorFactory.createSingleFileDescriptor(),
                null
        ));
        pythonPathField.setToolTipText("Path to python3 executable (leave empty to use system python)");
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        envPanel.add(pythonPathField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 0;
        envPanel.add(new JBLabel("frida-ps Path:"), gbc);

        fridaPsPathField = new JBTextField(30);
        fridaPsPathField.setToolTipText("Path to frida-ps (leave empty to use system frida-ps)");
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        envPanel.add(fridaPsPathField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.weightx = 0;
        envPanel.add(new JBLabel("frida-ls-devices Path:"), gbc);

        fridaLsDevicesPathField = new JBTextField(30);
        fridaLsDevicesPathField.setToolTipText("Path to frida-ls-devices (leave empty to use system frida-ls-devices)");
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        envPanel.add(fridaLsDevicesPathField, gbc);

        contentPanel.add(envPanel);
        contentPanel.add(Box.createVerticalStrut(16));

        // === 默认连接配置 ===
        contentPanel.add(createSectionLabel("Default Remote Connection"));
        contentPanel.add(Box.createVerticalStrut(8));

        JPanel connPanel = new JPanel(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = JBUI.insets(4);

        gbc.gridx = 0;
        gbc.gridy = 0;
        connPanel.add(new JBLabel("Default Host:"), gbc);

        defaultRemoteHostField = new JBTextField(20);
        defaultRemoteHostField.getEmptyText().setText("127.0.0.1");
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        connPanel.add(defaultRemoteHostField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        connPanel.add(new JBLabel("Default Port:"), gbc);

        defaultRemotePortField = new JBTextField(10);
        defaultRemotePortField.getEmptyText().setText("14725");
        gbc.gridx = 1;
        connPanel.add(defaultRemotePortField, gbc);

        JBLabel connHint = new JBLabel("<html><small style='color:gray'>Used for Remote/Gadget mode when not overridden in project settings</small></html>");
        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        connPanel.add(connHint, gbc);

        contentPanel.add(connPanel);
        contentPanel.add(Box.createVerticalStrut(16));

        // === 控制台配置 ===
        contentPanel.add(createSectionLabel("Console Settings"));
        contentPanel.add(Box.createVerticalStrut(8));

        JPanel consolePanel = new JPanel(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = JBUI.insets(4);

        gbc.gridx = 0;
        gbc.gridy = 0;
        consolePanel.add(new JBLabel("Max Console Lines:"), gbc);

        maxConsoleLinesField = new JBTextField(10);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        consolePanel.add(maxConsoleLinesField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        consolePanel.add(new JBLabel("Console Font Size:"), gbc);

        consoleFontSizeField = new JBTextField(10);
        gbc.gridx = 1;
        consolePanel.add(consoleFontSizeField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        autoScrollConsoleCheckBox = new JBCheckBox("Auto-scroll console to bottom");
        consolePanel.add(autoScrollConsoleCheckBox, gbc);

        contentPanel.add(consolePanel);
        contentPanel.add(Box.createVerticalStrut(16));

        // === 设备刷新 ===
        contentPanel.add(createSectionLabel("Device Management"));
        contentPanel.add(Box.createVerticalStrut(8));

        JPanel devicePanel = new JPanel(new GridBagLayout());
        gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = JBUI.insets(4);

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridwidth = 2;
        autoRefreshDevicesCheckBox = new JBCheckBox("Auto-refresh device list");
        devicePanel.add(autoRefreshDevicesCheckBox, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        devicePanel.add(new JBLabel("Refresh Interval (seconds):"), gbc);

        refreshDeviceIntervalField = new JBTextField(10);
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        devicePanel.add(refreshDeviceIntervalField, gbc);

        contentPanel.add(devicePanel);
        contentPanel.add(Box.createVerticalStrut(16));

        // === 其他配置 ===
        contentPanel.add(createSectionLabel("Other Settings"));
        contentPanel.add(Box.createVerticalStrut(8));

        JPanel otherPanel = new JPanel();
        otherPanel.setLayout(new BoxLayout(otherPanel, BoxLayout.Y_AXIS));

        autoSyncTemplatesCheckBox = new JBCheckBox("Auto-sync templates on startup");
        otherPanel.add(autoSyncTemplatesCheckBox);
        otherPanel.add(Box.createVerticalStrut(4));

        showKeyboardHintsCheckBox = new JBCheckBox("Show keyboard shortcuts hints");
        otherPanel.add(showKeyboardHintsCheckBox);
        otherPanel.add(Box.createVerticalStrut(4));

        verboseModeCheckBox = new JBCheckBox("Verbose mode (show detailed logs)");
        otherPanel.add(verboseModeCheckBox);

        contentPanel.add(otherPanel);

        mainPanel.add(new JBScrollPane(contentPanel), BorderLayout.CENTER);

        reset();
        return mainPanel;
    }

    /**
     * 创建分节标题标签。
     * @param text 标题文本
     * @return 标签组件
     */
    private JBLabel createSectionLabel(String text) {
        JBLabel label = new JBLabel(text);
        label.setFont(label.getFont().deriveFont(Font.BOLD, 13f));
        return label;
    }

    /**
     * 判断设置是否发生修改。
     * @return true 表示已修改
     */
    @Override
    public boolean isModified() {
        if (!fridaPathField.getText().equals(settings.fridaPath)) return true;
        if (!pythonPathField.getText().equals(settings.pythonPath)) return true;
        if (!fridaPsPathField.getText().equals(settings.fridaPsPath)) return true;
        if (!fridaLsDevicesPathField.getText().equals(settings.fridaLsDevicesPath)) return true;
        if (!defaultRemoteHostField.getText().equals(settings.defaultRemoteHost)) return true;
        if (!defaultRemotePortField.getText().equals(String.valueOf(settings.defaultRemotePort))) return true;
        if (!maxConsoleLinesField.getText().equals(String.valueOf(settings.maxConsoleLines))) return true;
        if (!consoleFontSizeField.getText().equals(String.valueOf(settings.consoleFontSize))) return true;
        if (autoScrollConsoleCheckBox.isSelected() != settings.autoScrollConsole) return true;
        if (autoSyncTemplatesCheckBox.isSelected() != settings.autoSyncTemplates) return true;
        if (showKeyboardHintsCheckBox.isSelected() != settings.showKeyboardHints) return true;
        if (verboseModeCheckBox.isSelected() != settings.verboseMode) return true;
        if (autoRefreshDevicesCheckBox.isSelected() != settings.autoRefreshDevices) return true;
        if (!refreshDeviceIntervalField.getText().equals(String.valueOf(settings.refreshDeviceIntervalSeconds))) return true;
        return false;
    }

    /**
     * 应用设置改动。
     */
    @Override
    public void apply() {
        settings.fridaPath = fridaPathField.getText().trim();
        settings.pythonPath = pythonPathField.getText().trim();
        settings.fridaPsPath = fridaPsPathField.getText().trim();
        settings.fridaLsDevicesPath = fridaLsDevicesPathField.getText().trim();
        settings.defaultRemoteHost = defaultRemoteHostField.getText().trim();

        try {
            settings.defaultRemotePort = Integer.parseInt(defaultRemotePortField.getText().trim());
        } catch (NumberFormatException e) {
            settings.defaultRemotePort = 14725;
        }

        try {
            settings.maxConsoleLines = Integer.parseInt(maxConsoleLinesField.getText().trim());
        } catch (NumberFormatException e) {
            settings.maxConsoleLines = 10000;
        }

        try {
            settings.consoleFontSize = Integer.parseInt(consoleFontSizeField.getText().trim());
        } catch (NumberFormatException e) {
            settings.consoleFontSize = 12;
        }

        try {
            settings.refreshDeviceIntervalSeconds = Integer.parseInt(refreshDeviceIntervalField.getText().trim());
        } catch (NumberFormatException e) {
            settings.refreshDeviceIntervalSeconds = 5;
        }

        settings.autoScrollConsole = autoScrollConsoleCheckBox.isSelected();
        settings.autoSyncTemplates = autoSyncTemplatesCheckBox.isSelected();
        settings.showKeyboardHints = showKeyboardHintsCheckBox.isSelected();
        settings.verboseMode = verboseModeCheckBox.isSelected();
        settings.autoRefreshDevices = autoRefreshDevicesCheckBox.isSelected();
    }

    /**
     * 重置 UI 为当前配置。
     */
    @Override
    public void reset() {
        fridaPathField.setText(settings.fridaPath);
        pythonPathField.setText(settings.pythonPath);
        fridaPsPathField.setText(settings.fridaPsPath);
        fridaLsDevicesPathField.setText(settings.fridaLsDevicesPath);
        defaultRemoteHostField.setText(settings.defaultRemoteHost);
        defaultRemotePortField.setText(String.valueOf(settings.defaultRemotePort));
        maxConsoleLinesField.setText(String.valueOf(settings.maxConsoleLines));
        consoleFontSizeField.setText(String.valueOf(settings.consoleFontSize));
        autoScrollConsoleCheckBox.setSelected(settings.autoScrollConsole);
        autoSyncTemplatesCheckBox.setSelected(settings.autoSyncTemplates);
        showKeyboardHintsCheckBox.setSelected(settings.showKeyboardHints);
        verboseModeCheckBox.setSelected(settings.verboseMode);
        autoRefreshDevicesCheckBox.setSelected(settings.autoRefreshDevices);
        refreshDeviceIntervalField.setText(String.valueOf(settings.refreshDeviceIntervalSeconds));
    }
}
