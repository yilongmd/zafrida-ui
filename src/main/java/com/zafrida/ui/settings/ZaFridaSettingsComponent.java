package com.zafrida.ui.settings;

import com.intellij.icons.AllIcons;
import com.intellij.ui.components.JBCheckBox;
import com.intellij.ui.components.JBList;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.components.JBTextField;
import com.intellij.util.ui.FormBuilder;
import com.intellij.openapi.ui.Messages;
import org.jetbrains.annotations.NotNull;

import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;
/**
 * [UI组件] 全局设置面板的 Swing 实现。
 * <p>
 * <strong>包含控件：</strong>
 * <ul>
 * <li>Frida 工具链路径输入框 (frida, frida-ps, frida-ls-devices)。</li>
 * <li>日志目录配置。</li>
 * <li>远程主机列表 (Remote Hosts) 管理。</li>
 * </ul>
 * 它是 {@link ZaFridaSettingsConfigurable} 的视图层。
 */
public final class ZaFridaSettingsComponent {

    /** frida 路径输入框 */
    private final JBTextField fridaField = new JBTextField();
    /** frida-ps 路径输入框 */
    private final JBTextField fridaPsField = new JBTextField();
    /** frida-ls-devices 路径输入框 */
    private final JBTextField fridaLsDevicesField = new JBTextField();
    /** 日志目录输入框 */
    private final JBTextField logsDirField = new JBTextField();
    /** 默认远程主机输入框 */
    private final JBTextField defaultRemoteHostField = new JBTextField();
    /** 默认远程端口输入框 */
    private final JBTextField defaultRemotePortField = new JBTextField();
    /** 是否使用 IDE 脚本选择器 */
    private final JBCheckBox useIdeScriptChooserCheckBox = new JBCheckBox("Use IDE script chooser (Project tree)");

    /** 远程主机列表模型 */
    private final DefaultListModel<String> remoteModel = new DefaultListModel<>();
    /** 远程主机列表组件 */
    private final JBList<String> remoteList = new JBList<>(remoteModel);
    /** 添加远程主机按钮 */
    private final JButton addRemoteBtn = new JButton("Add");
    /** 移除远程主机按钮 */
    private final JButton removeRemoteBtn = new JButton("Remove");

    /** 根面板 */
    private final JComponent panel;

    /**
     * 构造函数，初始化 UI。
     */
    public ZaFridaSettingsComponent() {
        addRemoteBtn.setIcon(AllIcons.General.Add);
        removeRemoteBtn.setIcon(AllIcons.General.Remove);

        JPanel remoteButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        remoteButtons.add(addRemoteBtn);
        remoteButtons.add(removeRemoteBtn);

        JPanel remotePanel = new JPanel(new BorderLayout(0, 8));
        remotePanel.add(new JBScrollPane(remoteList), BorderLayout.CENTER);
        remotePanel.add(remoteButtons, BorderLayout.SOUTH);

        defaultRemoteHostField.setColumns(16);
        defaultRemotePortField.setColumns(6);
        defaultRemoteHostField.getEmptyText().setText("127.0.0.1");
        defaultRemotePortField.getEmptyText().setText("14725");
        JPanel defaultRemotePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        defaultRemotePanel.add(defaultRemoteHostField);
        defaultRemotePanel.add(new JLabel(":"));
        defaultRemotePanel.add(defaultRemotePortField);

        panel = FormBuilder.createFormBuilder()
                .addLabeledComponent("frida", fridaField, 1, false)
                .addLabeledComponent("frida-ps", fridaPsField, 1, false)
                .addLabeledComponent("frida-ls-devices", fridaLsDevicesField, 1, false)
                .addLabeledComponent("Logs Dir (relative to project)", logsDirField, 1, false)
                .addLabeledComponent("Script Chooser", useIdeScriptChooserCheckBox, 1, false)
                .addLabeledComponent("Default Remote Host:Port", defaultRemotePanel, 1, false)
                .addLabeledComponent("Remote Hosts (host:port)", remotePanel, 1, false)
                .getPanel();

        addRemoteBtn.addActionListener(e -> {
            String defHost = textOrDefault(defaultRemoteHostField.getText(), "127.0.0.1");
            String defPort = textOrDefault(defaultRemotePortField.getText(), "14725");
            String initial = defHost + ":" + defPort;
            String input = Messages.showInputDialog(panel, "host:port", "ZAFrida", null, initial, null);
            if (input == null) return;
            String h = input.trim();
            if (!h.isEmpty() && !containsRemote(h)) {
                remoteModel.addElement(h);
            }
        });

        removeRemoteBtn.addActionListener(e -> {
            int idx = remoteList.getSelectedIndex();
            if (idx >= 0) remoteModel.remove(idx);
        });
    }

    /**
     * 获取根面板。
     * @return 面板组件
     */
    public @NotNull JComponent getPanel() {
        return panel;
    }

    /**
     * 使用状态重置 UI。
     * @param state 配置状态
     */
    public void reset(@NotNull ZaFridaSettingsState state) {
        fridaField.setText(orDefault(state.fridaExecutable, "frida"));
        fridaPsField.setText(orDefault(state.fridaPsExecutable, "frida-ps"));
        fridaLsDevicesField.setText(orDefault(state.fridaLsDevicesExecutable, "frida-ls-devices"));
        logsDirField.setText(orDefault(state.logsDirName, "zafrida-logs"));
        defaultRemoteHostField.setText(orDefault(state.defaultRemoteHost, "127.0.0.1"));
        defaultRemotePortField.setText(String.valueOf(state.defaultRemotePort > 0 ? state.defaultRemotePort : 14725));
        useIdeScriptChooserCheckBox.setSelected(state.useIdeScriptChooser);

        remoteModel.clear();
        if (state.remoteHosts != null) {
            for (String h : state.remoteHosts) {
                if (h != null && !h.isBlank()) remoteModel.addElement(h);
            }
        }
    }

    /**
     * 将 UI 值写回状态对象。
     * @param state 配置状态
     */
    public void applyTo(@NotNull ZaFridaSettingsState state) {
        state.fridaExecutable = textOrDefault(fridaField.getText(), "frida");
        state.fridaPsExecutable = textOrDefault(fridaPsField.getText(), "frida-ps");
        state.fridaLsDevicesExecutable = textOrDefault(fridaLsDevicesField.getText(), "frida-ls-devices");
        state.logsDirName = textOrDefault(logsDirField.getText(), "zafrida-logs");
        state.defaultRemoteHost = textOrDefault(defaultRemoteHostField.getText(), "127.0.0.1");
        state.defaultRemotePort = parsePort(defaultRemotePortField.getText(), 14725);
        state.useIdeScriptChooser = useIdeScriptChooserCheckBox.isSelected();

        List<String> remotes = new ArrayList<>();
        for (int i = 0; i < remoteModel.size(); i++) {
            remotes.add(remoteModel.getElementAt(i));
        }
        state.remoteHosts = remotes;
    }

    /**
     * 判断远程主机是否已存在。
     * @param host 主机字符串
     * @return true 表示已存在
     */
    private boolean containsRemote(String host) {
        for (int i = 0; i < remoteModel.size(); i++) {
            if (host.equals(remoteModel.getElementAt(i))) return true;
        }
        return false;
    }

    /**
     * 获取文本或默认值（允许空白）。
     * @param s 输入文本
     * @param d 默认值
     * @return 结果字符串
     */
    private static String textOrDefault(String s, String d) {
        if (s == null) return d;
        String t = s.trim();
        return t.isEmpty() ? d : t;
    }

    /**
     * 获取文本或默认值（空白视为默认）。
     * @param s 输入文本
     * @param d 默认值
     * @return 结果字符串
     */
    private static String orDefault(String s, String d) {
        if (s == null || s.trim().isEmpty()) return d;
        return s;
    }

    /**
     * 解析端口文本。
     * @param s 输入文本
     * @param fallback 回退值
     * @return 端口值
     */
    private static int parsePort(String s, int fallback) {
        if (s == null || s.trim().isEmpty()) return fallback;
        try {
            int v = Integer.parseInt(s.trim());
            return v > 0 ? v : fallback;
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
