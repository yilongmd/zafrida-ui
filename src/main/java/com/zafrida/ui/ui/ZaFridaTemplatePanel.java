package com.zafrida.ui.ui;

import com.intellij.openapi.Disposable;
import com.intellij.icons.AllIcons;
import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.fileEditor.FileDocumentManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.ui.TitledSeparator;
import com.intellij.ui.components.JBCheckBox;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.components.JBTextField;
import com.zafrida.ui.fridaproject.ZaFridaFridaProject;
import com.zafrida.ui.fridaproject.ZaFridaPlatform;
import com.zafrida.ui.fridaproject.ZaFridaProjectListener;
import com.zafrida.ui.fridaproject.ZaFridaProjectManager;
import com.zafrida.ui.templates.TemplateScriptManipulator;
import com.zafrida.ui.templates.ZaFridaScriptSkeleton;
import com.zafrida.ui.templates.ZaFridaTemplate;
import com.zafrida.ui.templates.ZaFridaTemplateCategory;
import com.zafrida.ui.templates.ZaFridaTemplateFile;
import com.zafrida.ui.templates.ZaFridaTemplateFileStore;
import com.zafrida.ui.typings.TypingsInstaller;
import com.zafrida.ui.util.ProjectFileUtil;
import com.zafrida.ui.util.ZaFridaNotifier;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class ZaFridaTemplatePanel extends JPanel implements Disposable {

    private final @NotNull Project project;
    private final @NotNull ZaFridaProjectManager projectManager;

    private final JBTextField scriptField = new JBTextField();
    private final JButton chooseScriptBtn = new JButton("Choose...");
    private final JButton createScriptBtn = new JButton("New Script");
    private final JButton installTypingsBtn = new JButton("Install Typings");
    private final JButton refreshBtn = new JButton("Refresh");
    private final JButton addTemplateBtn = new JButton("Add Template");
    private final JButton deleteTemplateBtn = new JButton("Delete Template");

    private final JPanel templatesContainer = new JPanel();
    private final Map<String, JBCheckBox> checkBoxes = new LinkedHashMap<>();
    private final Map<String, ZaFridaTemplateFile> templateFiles = new LinkedHashMap<>();

    private @Nullable VirtualFile currentScript;
    private @Nullable ZaFridaPlatform activePlatform;

    public ZaFridaTemplatePanel(@NotNull Project project) {
        super(new BorderLayout());
        this.project = project;
        this.projectManager = project.getService(ZaFridaProjectManager.class);

        scriptField.setEditable(false);
        chooseScriptBtn.setIcon(AllIcons.Actions.OpenFile);
        createScriptBtn.setIcon(AllIcons.Actions.NewFile);
        installTypingsBtn.setIcon(AllIcons.Actions.Download);
        refreshBtn.setIcon(AllIcons.Actions.Refresh);
        addTemplateBtn.setIcon(AllIcons.General.Add);
        deleteTemplateBtn.setIcon(AllIcons.General.Remove);

        JPanel header = new JPanel(new BorderLayout(8, 0));

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        left.add(new JLabel("Script:"));
        scriptField.setColumns(20);
        left.add(scriptField);
        left.add(chooseScriptBtn);
        left.add(createScriptBtn);
        left.add(installTypingsBtn);
        left.add(addTemplateBtn);
        left.add(deleteTemplateBtn);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 6));
        right.add(refreshBtn);

        header.add(left, BorderLayout.WEST);
        header.add(right, BorderLayout.EAST);

        add(header, BorderLayout.NORTH);

        templatesContainer.setLayout(new BoxLayout(templatesContainer, BoxLayout.Y_AXIS));
        add(new JBScrollPane(templatesContainer), BorderLayout.CENTER);

        bindProjectListener();
        refreshTemplates();
        bindActions();

        setCurrentScriptFile(null);
    }

    public void setCurrentScriptFile(@Nullable VirtualFile file) {
        this.currentScript = file;
        scriptField.setText(file == null ? "" : file.getPath());
        updateCheckboxState();
    }

    public @Nullable VirtualFile getCurrentScriptFile() {
        return currentScript;
    }

    private void refreshTemplates() {
        templatesContainer.removeAll();
        checkBoxes.clear();
        templateFiles.clear();

        ZaFridaPlatform platform = getActivePlatform();
        boolean hasPlatform = platform != null;
        addTemplateBtn.setEnabled(hasPlatform);
        deleteTemplateBtn.setEnabled(hasPlatform);
        if (!hasPlatform) {
            templatesContainer.revalidate();
            templatesContainer.repaint();
            return;
        }

        List<ZaFridaTemplateFile> files = ZaFridaTemplateFileStore.load(project, platform);
        Map<ZaFridaTemplateCategory, List<ZaFridaTemplateFile>> grouped = new EnumMap<>(ZaFridaTemplateCategory.class);
        for (ZaFridaTemplateFile file : files) {
            grouped.computeIfAbsent(file.getTemplate().getCategory(), k -> new ArrayList<>()).add(file);
            templateFiles.put(file.getTemplate().getId(), file);
        }

        for (ZaFridaTemplateCategory cat : grouped.keySet()) {
            List<ZaFridaTemplateFile> list = grouped.getOrDefault(cat, List.of());
            if (list.isEmpty()) continue;

            templatesContainer.add(new TitledSeparator(cat.name()));

            for (ZaFridaTemplateFile entry : list) {
                ZaFridaTemplate t = entry.getTemplate();
                JBCheckBox cb = new JBCheckBox(t.getTitle());
                cb.setToolTipText(t.getDescription());
                cb.addActionListener(e -> onToggle(t, cb.isSelected()));
                checkBoxes.put(t.getId(), cb);
                templatesContainer.add(cb);
            }
            templatesContainer.add(Box.createVerticalStrut(10));
        }

        templatesContainer.revalidate();
        templatesContainer.repaint();
        updateCheckboxState();
    }

    private void bindActions() {
        chooseScriptBtn.addActionListener(e -> {
            VirtualFile file = ProjectFileUtil.chooseJavaScriptFile(project);
            if (file != null) {
                setCurrentScriptFile(file);
            }
        });

        createScriptBtn.addActionListener(e -> {
            VirtualFile vf = ProjectFileUtil.createScript(project, "zafrida/agent.js", ZaFridaScriptSkeleton.TEXT);
            if (vf != null) {
                ZaFridaNotifier.info(project, "ZAFrida", "Created script: zafrida/agent.js");
                setCurrentScriptFile(vf);
            } else {
                ZaFridaNotifier.warn(project, "ZAFrida", "Failed to create script (project basePath?)");
            }
        });

        installTypingsBtn.addActionListener(e -> TypingsInstaller.install(project));

        refreshBtn.addActionListener(e -> refreshTemplates());

        addTemplateBtn.addActionListener(e -> addTemplate());
        deleteTemplateBtn.addActionListener(e -> deleteTemplate());
    }

    private void updateCheckboxState() {
        VirtualFile file = currentScript;
        boolean enabled = file != null && file.isValid();
        for (JBCheckBox cb : checkBoxes.values()) {
            cb.setEnabled(enabled);
        }

        if (!enabled) {
            for (JBCheckBox cb : checkBoxes.values()) {
                cb.setSelected(false);
            }
            return;
        }

        Document doc = FileDocumentManager.getInstance().getDocument(file);
        if (doc == null) return;
        String text = doc.getText();

        for (Map.Entry<String, JBCheckBox> e : checkBoxes.entrySet()) {
            Boolean st = TemplateScriptManipulator.isTemplateEnabled(text, e.getKey());
            e.getValue().setSelected(Boolean.TRUE.equals(st));
        }
    }

    private void onToggle(@NotNull ZaFridaTemplate template, boolean selected) {
        VirtualFile file = currentScript;
        if (file == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Choose a script file first");
            updateCheckboxState();
            return;
        }

        Document doc = FileDocumentManager.getInstance().getDocument(file);
        if (doc == null) {
            ZaFridaNotifier.error(project, "ZAFrida", "Cannot get document for file: " + file.getPath());
            updateCheckboxState();
            return;
        }

        WriteCommandAction.runWriteCommandAction(project, () -> {
            TemplateScriptManipulator.setTemplateEnabled(doc, template, selected);
            FileDocumentManager.getInstance().saveDocument(doc);
        });
        updateCheckboxState();
    }

    private void bindProjectListener() {
        project.getMessageBus().connect(this).subscribe(ZaFridaProjectManager.TOPIC, new ZaFridaProjectListener() {
            @Override
            public void onActiveProjectChanged(@Nullable ZaFridaFridaProject newProject) {
                refreshTemplates();
            }
        });
    }

    private @Nullable ZaFridaPlatform getActivePlatform() {
        ZaFridaFridaProject active = projectManager.getActiveProject();
        if (active == null) return null;
        activePlatform = active.getPlatform();
        return activePlatform;
    }

    private void addTemplate() {
        ZaFridaPlatform platform = getActivePlatform();
        if (platform == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Select a project to add templates");
            return;
        }
        String name = Messages.showInputDialog(
                project,
                "Template name:",
                "Add Template",
                null
        );
        if (name == null) return;
        String trimmed = name.trim();
        if (trimmed.isEmpty()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Template name is empty");
            return;
        }
        if (ZaFridaTemplateFileStore.createTemplate(project, platform, trimmed) == null) {
            ZaFridaNotifier.error(project, "ZAFrida", "Failed to create template file");
            return;
        }
        refreshTemplates();
    }

    private void deleteTemplate() {
        if (templateFiles.isEmpty()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "No templates to delete");
            return;
        }
        String[] options = templateFiles.values().stream()
                .map(entry -> entry.getTemplate().getTitle())
                .toArray(String[]::new);
        String choice = Messages.showChooseDialog(
                project,
                "Select template to delete:",
                "Delete Template",
                options,
                options[0],
                null
        );
        if (choice == null) return;
        ZaFridaTemplateFile selected = templateFiles.values().stream()
                .filter(entry -> entry.getTemplate().getTitle().equals(choice))
                .findFirst()
                .orElse(null);
        if (selected == null) return;
        if (!ZaFridaTemplateFileStore.deleteTemplate(selected.getPath())) {
            ZaFridaNotifier.error(project, "ZAFrida", "Failed to delete template file");
            return;
        }
        refreshTemplates();
    }

    @Override
    public void dispose() {
        // no-op
    }
}
