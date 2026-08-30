package com.zafrida.ui.settings;

import com.intellij.icons.AllIcons;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.project.ProjectManager;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.ui.TextFieldWithBrowseButton;
import com.intellij.openapi.vfs.LocalFileSystem;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.ui.components.JBCheckBox;
import com.intellij.ui.components.JBList;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.components.JBTextField;
import com.intellij.util.ui.FormBuilder;
import com.zafrida.ui.util.ProjectFileUtil;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public final class ZaFridaSettingsComponent {

    private static final String ZAFRIDA_DIR_NAME = ".zafrida";
    private static final String TEMPLATES_DIR_NAME = "templates";

    private final JBTextField fridaField = new JBTextField();
    private final JBTextField fridaPsField = new JBTextField();
    private final JBTextField fridaLsDevicesField = new JBTextField();
    private final JBTextField fridaVersionField = new JBTextField();
    private final JBTextField vscodeField = new JBTextField();
    private final JBTextField editor010Field = new JBTextField();
    private final JBTextField logsDirField = new JBTextField();
    private final JBTextField defaultRemoteHostField = new JBTextField();
    private final JBTextField defaultRemotePortField = new JBTextField();
    private final JBCheckBox useIdeScriptChooserCheckBox = new JBCheckBox("Use IDE script chooser (Project tree)");
    private final JBCheckBox enableSkillsHttpApiCheckBox = new JBCheckBox("Enable Skills local HTTP API");
    private final JBTextField skillsApiPortField = new JBTextField();
    private final JButton startSkillsApiBtn = new JButton("Start");
    private final JButton stopSkillsApiBtn = new JButton("Stop");
    private final JLabel skillsApiStatusLabel = new JLabel("Stopped");
    private final JComboBox<TemplateRootOption> templatesRootModeCombo = new JComboBox<>();
    private final TextFieldWithBrowseButton templatesRootPathField = new TextFieldWithBrowseButton();

    private final DefaultListModel<String> remoteModel = new DefaultListModel<>();
    private final JBList<String> remoteList = new JBList<>(remoteModel);
    private final JButton addRemoteBtn = new JButton("Add");
    private final JButton removeRemoteBtn = new JButton("Remove");

    private final JComponent panel;
    private @Nullable Runnable startSkillsApiHandler;
    private @Nullable Runnable stopSkillsApiHandler;
    private boolean skillsApiRunning = false;
    private boolean updatingUi = false;

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
        fridaVersionField.setColumns(6);
        skillsApiPortField.setColumns(6);
        defaultRemoteHostField.getEmptyText().setText("127.0.0.1");
        defaultRemotePortField.getEmptyText().setText("14725");
        skillsApiPortField.getEmptyText().setText(String.valueOf(ZaFridaSettingsState.DEFAULT_SKILLS_API_PORT));
        fridaVersionField.getEmptyText().setText(ZaFridaSettingsService.DEFAULT_FRIDA_VERSION);
        fridaVersionField.setToolTipText(
                "Fallback used before the active project's Python environment version has been detected"
        );
        vscodeField.getEmptyText().setText("code / code.cmd / Code.exe");
        vscodeField.setToolTipText("Optional. Used for opening log file in VS Code.");
        editor010Field.getEmptyText().setText("/Applications/010 Editor.app / 010Editor.exe");
        editor010Field.setToolTipText("Optional. Used for opening file in 010 Editor.");
        JPanel defaultRemotePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        defaultRemotePanel.add(defaultRemoteHostField);
        defaultRemotePanel.add(new JLabel(":"));
        defaultRemotePanel.add(defaultRemotePortField);

        startSkillsApiBtn.setIcon(AllIcons.Actions.Execute);
        stopSkillsApiBtn.setIcon(AllIcons.Actions.Suspend);
        JPanel skillsApiPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        skillsApiPanel.add(enableSkillsHttpApiCheckBox);
        skillsApiPanel.add(new JLabel("Port"));
        skillsApiPanel.add(skillsApiPortField);
        skillsApiPanel.add(startSkillsApiBtn);
        skillsApiPanel.add(stopSkillsApiBtn);
        skillsApiPanel.add(skillsApiStatusLabel);

        templatesRootModeCombo.addItem(new TemplateRootOption(
                ZaFridaSettingsState.TEMPLATE_ROOT_MODE_SYSTEM,
                "System (User Home)"
        ));
        templatesRootModeCombo.addItem(new TemplateRootOption(
                ZaFridaSettingsState.TEMPLATE_ROOT_MODE_IDE,
                "IDE Project Root"
        ));
        templatesRootModeCombo.addActionListener(e -> updateTemplatesRootPathField());

        templatesRootPathField.getTextField().setEditable(false);
        templatesRootPathField.setToolTipText("Open templates folder");
        templatesRootPathField.addActionListener(e -> locateTemplatesFolder());

        panel = FormBuilder.createFormBuilder()
                .addLabeledComponent("frida", fridaField, 1, false)
                .addLabeledComponent("frida-ps", fridaPsField, 1, false)
                .addLabeledComponent("frida-ls-devices", fridaLsDevicesField, 1, false)
                .addLabeledComponent("Frida Version (fallback)", fridaVersionField, 1, false)
                .addLabeledComponent("VS Code (optional)", vscodeField, 1, false)
                .addLabeledComponent("010 Editor (optional)", editor010Field, 1, false)
                .addLabeledComponent("Logs Dir (relative to project)", logsDirField, 1, false)
                .addLabeledComponent("Templates Root", templatesRootModeCombo, 1, false)
                .addLabeledComponent("Templates Path", templatesRootPathField, 1, false)
                .addLabeledComponent("Script Chooser", useIdeScriptChooserCheckBox, 1, false)
                .addLabeledComponent("Skills HTTP API", skillsApiPanel, 1, false)
                .addLabeledComponent("Default Remote Host:Port", defaultRemotePanel, 1, false)
                .addLabeledComponent("Remote Hosts (host:port)", remotePanel, 1, false)
                .getPanel();

        addRemoteBtn.addActionListener(e -> {
            String defHost = textOrDefault(defaultRemoteHostField.getText(), "127.0.0.1");
            String defPort = textOrDefault(defaultRemotePortField.getText(), "14725");
            String initial = String.format("%s:%s", defHost, defPort);
            String input = Messages.showInputDialog(panel, "host:port", "ZAFrida", null, initial, null);
            if (input == null) {
                return;
            }
            String h = input.trim();
            if (!h.isEmpty() && !containsRemote(h)) {
                remoteModel.addElement(h);
            }
        });

        removeRemoteBtn.addActionListener(e -> {
            int idx = remoteList.getSelectedIndex();
            if (idx >= 0) {
                remoteModel.remove(idx);
            }
        });

        enableSkillsHttpApiCheckBox.addActionListener(e -> {
            if (updatingUi) {
                return;
            }
            updateSkillsApiControlsEnabled();
            if (enableSkillsHttpApiCheckBox.isSelected()) {
                if (startSkillsApiHandler != null) {
                    startSkillsApiHandler.run();
                }
                return;
            }
            if (stopSkillsApiHandler != null) {
                stopSkillsApiHandler.run();
            }
        });

        startSkillsApiBtn.addActionListener(e -> {
            if (startSkillsApiHandler != null) {
                startSkillsApiHandler.run();
            }
        });

        stopSkillsApiBtn.addActionListener(e -> {
            if (stopSkillsApiHandler != null) {
                stopSkillsApiHandler.run();
            }
        });

        updateSkillsApiControlsEnabled();
    }

    public @NotNull JComponent getPanel() {
        return panel;
    }

    public void bindSkillsApiActions(@Nullable Runnable startHandler, @Nullable Runnable stopHandler) {
        this.startSkillsApiHandler = startHandler;
        this.stopSkillsApiHandler = stopHandler;
        updateSkillsApiControlsEnabled();
    }

    public void setSkillsApiStatus(@NotNull String status, boolean running) {
        skillsApiStatusLabel.setText(status);
        skillsApiRunning = running;
        updateSkillsApiControlsEnabled();
    }

    public void showSkillsApiTip(@NotNull String message, boolean error) {
        if (error) {
            Messages.showErrorDialog(panel, message, "ZAFrida");
            return;
        }
        Messages.showInfoMessage(panel, message, "ZAFrida");
    }

    public boolean isSkillsApiEnabled() {
        return enableSkillsHttpApiCheckBox.isSelected();
    }

    public int getSkillsApiPort() {
        return parsePort(skillsApiPortField.getText(), ZaFridaSettingsState.DEFAULT_SKILLS_API_PORT);
    }

    public void reset(@NotNull ZaFridaSettingsState state) {
        updatingUi = true;
        try {
            fridaField.setText(orDefault(state.fridaExecutable, "frida"));
            fridaPsField.setText(orDefault(state.fridaPsExecutable, "frida-ps"));
            fridaLsDevicesField.setText(orDefault(state.fridaLsDevicesExecutable, "frida-ls-devices"));
            fridaVersionField.setText(normalizeFridaVersion(state.fridaVersion));
            vscodeField.setText(orDefault(state.vscodeExecutable, ""));
            editor010Field.setText(orDefault(state.editor010Executable, ""));
            logsDirField.setText(orDefault(state.logsDirName, "zafrida-logs"));
            defaultRemoteHostField.setText(orDefault(state.defaultRemoteHost, "127.0.0.1"));
            int remotePort = 14725;
            if (state.defaultRemotePort > 0) {
                remotePort = state.defaultRemotePort;
            }
            defaultRemotePortField.setText(String.valueOf(remotePort));
            useIdeScriptChooserCheckBox.setSelected(state.useIdeScriptChooser);
            enableSkillsHttpApiCheckBox.setSelected(state.enableSkillsHttpApi);
            int apiPort = state.skillsApiPort;
            if (apiPort <= 0 || apiPort > 65535) {
                apiPort = ZaFridaSettingsState.DEFAULT_SKILLS_API_PORT;
            }
            skillsApiPortField.setText(String.valueOf(apiPort));
            setSelectedTemplatesRootMode(state.templatesRootMode);
            updateTemplatesRootPathField();

            remoteModel.clear();
            if (state.remoteHosts != null) {
                for (String h : state.remoteHosts) {
                    if (ZaStrUtil.isNotBlank(h)) {
                        remoteModel.addElement(h);
                    }
                }
            }
            skillsApiRunning = false;
            if (state.enableSkillsHttpApi) {
                skillsApiStatusLabel.setText("Stopped");
            } else {
                skillsApiStatusLabel.setText("Disabled");
            }
            updateSkillsApiControlsEnabled();
        } finally {
            updatingUi = false;
        }
    }

    public void applyTo(@NotNull ZaFridaSettingsState state) {
        state.fridaExecutable = textOrDefault(fridaField.getText(), "frida");
        state.fridaPsExecutable = textOrDefault(fridaPsField.getText(), "frida-ps");
        state.fridaLsDevicesExecutable = textOrDefault(fridaLsDevicesField.getText(), "frida-ls-devices");
        state.fridaVersion = normalizeFridaVersion(fridaVersionField.getText());
        state.vscodeExecutable = textOrDefault(vscodeField.getText(), "");
        state.editor010Executable = textOrDefault(editor010Field.getText(), "");
        state.logsDirName = textOrDefault(logsDirField.getText(), "zafrida-logs");
        state.defaultRemoteHost = textOrDefault(defaultRemoteHostField.getText(), "127.0.0.1");
        state.defaultRemotePort = parsePort(defaultRemotePortField.getText(), 14725);
        state.useIdeScriptChooser = useIdeScriptChooserCheckBox.isSelected();
        state.enableSkillsHttpApi = enableSkillsHttpApiCheckBox.isSelected();
        state.skillsApiPort = parsePort(skillsApiPortField.getText(), ZaFridaSettingsState.DEFAULT_SKILLS_API_PORT);
        state.templatesRootMode = getSelectedTemplatesRootMode();

        List<String> remotes = new ArrayList<>();
        for (int i = 0; i < remoteModel.size(); i++) {
            remotes.add(remoteModel.getElementAt(i));
        }
        state.remoteHosts = remotes;
    }

    private void updateTemplatesRootPathField() {
        String mode = getSelectedTemplatesRootMode();
        Path root = resolveTemplatesRootPreview(mode);
        if (root == null) {
            templatesRootPathField.setText("No open project");
            templatesRootPathField.setToolTipText("No open project");
            return;
        }
        templatesRootPathField.setText(root.toString());
        templatesRootPathField.setToolTipText(root.toString());
    }

    private void locateTemplatesFolder() {
        String mode = getSelectedTemplatesRootMode();
        Path root = resolveTemplatesRootPreview(mode);
        if (root == null) {
            Messages.showWarningDialog(panel, "No open project found to locate templates.", "ZAFrida");
            return;
        }
        if (ZaFridaSettingsState.TEMPLATE_ROOT_MODE_IDE.equals(mode)) {
            openTemplatesFolderInIde(root);
        } else {
            openTemplatesFolderInSystem(root);
        }
    }

    private void openTemplatesFolderInSystem(@NotNull Path root) {
        if (!Desktop.isDesktopSupported()) {
            Messages.showWarningDialog(panel, "Desktop open is not supported on this platform.", "ZAFrida");
            return;
        }
        Desktop desktop = Desktop.getDesktop();
        if (!desktop.isSupported(Desktop.Action.OPEN)) {
            Messages.showWarningDialog(panel, "Desktop open action is not supported on this platform.", "ZAFrida");
            return;
        }
        try {
            desktop.open(root.toFile());
        } catch (Exception e) {
            Messages.showErrorDialog(panel, String.format("Failed to open folder: %s", e.getMessage()), "ZAFrida");
        }
    }

    private void openTemplatesFolderInIde(@NotNull Path root) {
        Project project = resolveActiveProject();
        if (project == null) {
            Messages.showWarningDialog(panel, "No open project found to locate templates.", "ZAFrida");
            return;
        }
        VirtualFile dir = LocalFileSystem.getInstance().refreshAndFindFileByIoFile(root.toFile());
        if (dir == null) {
            Messages.showWarningDialog(panel, String.format("Templates folder not found: %s", root), "ZAFrida");
            return;
        }
        ProjectFileUtil.openAndSelectInProject(project, dir);
    }

    private @Nullable Path resolveTemplatesRootPreview(@NotNull String mode) {
        if (ZaFridaSettingsState.TEMPLATE_ROOT_MODE_IDE.equals(mode)) {
            Project project = resolveActiveProject();
            if (project == null) {
                return null;
            }
            String basePath = project.getBasePath();
            if (basePath == null || basePath.trim().isEmpty()) {
                return null;
            }
            return Paths.get(basePath, ZAFRIDA_DIR_NAME, TEMPLATES_DIR_NAME);
        }
        String userHome = System.getProperty("user.home");
        if (userHome == null || userHome.trim().isEmpty()) {
            return Paths.get(ZAFRIDA_DIR_NAME, TEMPLATES_DIR_NAME).toAbsolutePath();
        }
        return Paths.get(userHome, ZAFRIDA_DIR_NAME, TEMPLATES_DIR_NAME);
    }

    private @Nullable Project resolveActiveProject() {
        Project[] projects = ProjectManager.getInstance().getOpenProjects();
        if (projects.length == 0) {
            return null;
        }
        for (Project project : projects) {
            if (project != null && !project.isDisposed()) {
                return project;
            }
        }
        return null;
    }

    private @NotNull String getSelectedTemplatesRootMode() {
        TemplateRootOption option = (TemplateRootOption) templatesRootModeCombo.getSelectedItem();
        if (option == null) {
            return ZaFridaSettingsState.TEMPLATE_ROOT_MODE_SYSTEM;
        }
        return option.getId();
    }

    private void setSelectedTemplatesRootMode(@Nullable String mode) {
        String normalized = normalizeTemplatesRootMode(mode);
        int count = templatesRootModeCombo.getItemCount();
        for (int i = 0; i < count; i++) {
            TemplateRootOption option = templatesRootModeCombo.getItemAt(i);
            if (option != null && normalized.equals(option.getId())) {
                templatesRootModeCombo.setSelectedItem(option);
                return;
            }
        }
        if (count > 0) {
            templatesRootModeCombo.setSelectedIndex(0);
        }
    }

    private @NotNull String normalizeTemplatesRootMode(@Nullable String mode) {
        if (mode == null || mode.trim().isEmpty()) {
            return ZaFridaSettingsState.TEMPLATE_ROOT_MODE_SYSTEM;
        }
        String normalized = mode.trim();
        if (ZaFridaSettingsState.TEMPLATE_ROOT_MODE_IDE.equalsIgnoreCase(normalized)) {
            return ZaFridaSettingsState.TEMPLATE_ROOT_MODE_IDE;
        }
        return ZaFridaSettingsState.TEMPLATE_ROOT_MODE_SYSTEM;
    }

    private boolean containsRemote(String host) {
        for (int i = 0; i < remoteModel.size(); i++) {
            if (host.equals(remoteModel.getElementAt(i))) {
                return true;
            }
        }
        return false;
    }

    private static String textOrDefault(String s, String d) {
        if (ZaStrUtil.isBlank(s)) {
            return d;
        }
        return ZaStrUtil.trim(s);
    }

    private static String orDefault(String s, String d) {
        if (ZaStrUtil.isBlank(s)) {
            return d;
        }
        return s;
    }

    private void updateSkillsApiControlsEnabled() {
        boolean enabled = enableSkillsHttpApiCheckBox.isSelected();
        skillsApiPortField.setEnabled(enabled);
        if (!enabled) {
            startSkillsApiBtn.setEnabled(false);
            stopSkillsApiBtn.setEnabled(false);
            return;
        }
        startSkillsApiBtn.setEnabled(!skillsApiRunning);
        stopSkillsApiBtn.setEnabled(skillsApiRunning);
    }

    private static int parsePort(String s, int fallback) {
        if (ZaStrUtil.isBlank(s)) {
            return fallback;
        }
        try {
            int v = Integer.parseInt(s.trim());
            if (v > 0 && v <= 65535) {
                return v;
            }
            return fallback;
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static @NotNull String normalizeFridaVersion(@Nullable String versionText) {
        if (ZaStrUtil.isBlank(versionText)) {
            return ZaFridaSettingsService.DEFAULT_FRIDA_VERSION;
        }
        String normalized = versionText.trim();
        if (normalized.isEmpty()) {
            return ZaFridaSettingsService.DEFAULT_FRIDA_VERSION;
        }
        return normalized;
    }

    private static final class TemplateRootOption {
        private final String id;
        private final String label;

        private TemplateRootOption(@NotNull String id, @NotNull String label) {
            this.id = id;
            this.label = label;
        }

        public String getId() {
            return id;
        }

        @Override
        public String toString() {
            return label;
        }
    }
}
