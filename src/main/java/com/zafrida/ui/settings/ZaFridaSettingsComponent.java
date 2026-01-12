package com.zafrida.ui.settings;

import com.intellij.icons.AllIcons;
import com.intellij.ui.components.JBList;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.components.JBTextField;
import com.intellij.util.ui.FormBuilder;
import com.intellij.openapi.ui.Messages;
import org.jetbrains.annotations.NotNull;

import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.List;

public final class ZaFridaSettingsComponent {

    private final JBTextField fridaField = new JBTextField();
    private final JBTextField fridaPsField = new JBTextField();
    private final JBTextField fridaLsDevicesField = new JBTextField();
    private final JBTextField logsDirField = new JBTextField();

    private final DefaultListModel<String> remoteModel = new DefaultListModel<>();
    private final JBList<String> remoteList = new JBList<>(remoteModel);
    private final JButton addRemoteBtn = new JButton("Add");
    private final JButton removeRemoteBtn = new JButton("Remove");

    private final JComponent panel;

    public ZaFridaSettingsComponent() {
        addRemoteBtn.setIcon(AllIcons.General.Add);
        removeRemoteBtn.setIcon(AllIcons.General.Remove);

        JPanel remoteButtons = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        remoteButtons.add(addRemoteBtn);
        remoteButtons.add(removeRemoteBtn);

        JPanel remotePanel = new JPanel(new BorderLayout(0, 8));
        remotePanel.add(new JBScrollPane(remoteList), BorderLayout.CENTER);
        remotePanel.add(remoteButtons, BorderLayout.SOUTH);

        panel = FormBuilder.createFormBuilder()
                .addLabeledComponent("frida", fridaField, 1, false)
                .addLabeledComponent("frida-ps", fridaPsField, 1, false)
                .addLabeledComponent("frida-ls-devices", fridaLsDevicesField, 1, false)
                .addLabeledComponent("Logs Dir (relative to project)", logsDirField, 1, false)
                .addLabeledComponent("Remote Hosts (host:port)", remotePanel, 1, false)
                .getPanel();

        addRemoteBtn.addActionListener(e -> {
            String input = Messages.showInputDialog(panel, "host:port", "ZAFrida", null);
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

    public @NotNull JComponent getPanel() {
        return panel;
    }

    public void reset(@NotNull ZaFridaSettingsState state) {
        fridaField.setText(orDefault(state.fridaExecutable, "frida"));
        fridaPsField.setText(orDefault(state.fridaPsExecutable, "frida-ps"));
        fridaLsDevicesField.setText(orDefault(state.fridaLsDevicesExecutable, "frida-ls-devices"));
        logsDirField.setText(orDefault(state.logsDirName, "zafrida-logs"));

        remoteModel.clear();
        if (state.remoteHosts != null) {
            for (String h : state.remoteHosts) {
                if (h != null && !h.isBlank()) remoteModel.addElement(h);
            }
        }
    }

    public void applyTo(@NotNull ZaFridaSettingsState state) {
        state.fridaExecutable = textOrDefault(fridaField.getText(), "frida");
        state.fridaPsExecutable = textOrDefault(fridaPsField.getText(), "frida-ps");
        state.fridaLsDevicesExecutable = textOrDefault(fridaLsDevicesField.getText(), "frida-ls-devices");
        state.logsDirName = textOrDefault(logsDirField.getText(), "zafrida-logs");

        List<String> remotes = new ArrayList<>();
        for (int i = 0; i < remoteModel.size(); i++) {
            remotes.add(remoteModel.getElementAt(i));
        }
        state.remoteHosts = remotes;
    }

    private boolean containsRemote(String host) {
        for (int i = 0; i < remoteModel.size(); i++) {
            if (host.equals(remoteModel.getElementAt(i))) return true;
        }
        return false;
    }

    private static String textOrDefault(String s, String d) {
        if (s == null) return d;
        String t = s.trim();
        return t.isEmpty() ? d : t;
    }

    private static String orDefault(String s, String d) {
        if (s == null || s.trim().isEmpty()) return d;
        return s;
    }
}
