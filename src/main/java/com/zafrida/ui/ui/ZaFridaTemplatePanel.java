package com.zafrida.ui.ui;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.fileEditor.FileDocumentManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.icons.AllIcons;
import com.intellij.ui.TitledSeparator;
import com.intellij.ui.components.JBCheckBox;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.components.JBTextField;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.util.text.StringUtil;
import com.zafrida.ui.fridaproject.ZaFridaPlatform;
import com.zafrida.ui.templates.TemplateScriptManipulator;
import com.zafrida.ui.templates.ZaFridaScriptSkeleton;
import com.zafrida.ui.templates.ZaFridaTemplate;
import com.zafrida.ui.templates.ZaFridaTemplateCategory;
import com.zafrida.ui.templates.ZaFridaTemplateService;
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
    private final @NotNull ZaFridaTemplateService templateService;

    private final JBTextField scriptField = new JBTextField();
    private final JButton chooseScriptBtn = new JButton("Choose...");
    private final JButton createScriptBtn = new JButton("New Script");
    private final JButton installTypingsBtn = new JButton("Install Typings");
    private final JButton refreshBtn = new JButton("Refresh");
    private final JButton addTemplateBtn = new JButton("Add Template");
    private final JButton removeTemplateBtn = new JButton("Remove Template");

    private final JPanel templatesContainer = new JPanel();
    private final Map<String, JBCheckBox> checkBoxes = new LinkedHashMap<>();

    private @Nullable VirtualFile currentScript;
    private @Nullable ZaFridaPlatform currentPlatform;

    public ZaFridaTemplatePanel(@NotNull Project project) {
        super(new BorderLayout());
        this.project = project;
        this.templateService = project.getService(ZaFridaTemplateService.class);

        scriptField.setEditable(false);
        scriptField.setColumns(22);
        chooseScriptBtn.setIcon(AllIcons.Actions.Open);
        createScriptBtn.setIcon(AllIcons.Actions.NewFolder);
        installTypingsBtn.setIcon(AllIcons.Actions.Download);
        refreshBtn.setIcon(AllIcons.Actions.Refresh);
        addTemplateBtn.setIcon(AllIcons.General.Add);
        removeTemplateBtn.setIcon(AllIcons.General.Remove);

        JPanel header = new JPanel(new BorderLayout(8, 0));

        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        left.add(new JLabel("Script:"));
        left.add(scriptField);
        left.add(chooseScriptBtn);
        left.add(createScriptBtn);
        left.add(installTypingsBtn);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 6));
        right.add(addTemplateBtn);
        right.add(removeTemplateBtn);
        right.add(refreshBtn);

        header.add(left, BorderLayout.WEST);
        header.add(right, BorderLayout.EAST);

        add(header, BorderLayout.NORTH);

        templatesContainer.setLayout(new BoxLayout(templatesContainer, BoxLayout.Y_AXIS));
        add(new JBScrollPane(templatesContainer), BorderLayout.CENTER);

        buildTemplatesUI();
        bindActions();

        setCurrentScriptFile(null);
    }

    public void setCurrentScriptFile(@Nullable VirtualFile file) {
        this.currentScript = file;
        scriptField.setText(file == null ? "" : file.getPath());
        updateCheckboxState();
    }

    public void setCurrentPlatform(@Nullable ZaFridaPlatform platform) {
        this.currentPlatform = platform;
        buildTemplatesUI();
        updateCheckboxState();
    }

    public @Nullable VirtualFile getCurrentScriptFile() {
        return currentScript;
    }

    private void buildTemplatesUI() {
        templatesContainer.removeAll();
        checkBoxes.clear();

        List<ZaFridaTemplate> all = filterTemplatesForPlatform(templateService.all());

        Map<ZaFridaTemplateCategory, List<ZaFridaTemplate>> grouped = new EnumMap<>(ZaFridaTemplateCategory.class);
        for (ZaFridaTemplate t : all) {
            grouped.computeIfAbsent(t.getCategory(), k -> new ArrayList<>()).add(t);
        }

        for (ZaFridaTemplateCategory cat : ZaFridaTemplateCategory.values()) {
            List<ZaFridaTemplate> list = grouped.getOrDefault(cat, List.of());
            if (list.isEmpty()) continue;

            templatesContainer.add(new TitledSeparator(cat.name()));

            for (ZaFridaTemplate t : list) {
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

        refreshBtn.addActionListener(e -> {
            templateService.reload();
            buildTemplatesUI();
            updateCheckboxState();
        });

        addTemplateBtn.addActionListener(e -> onAddTemplate());
        removeTemplateBtn.addActionListener(e -> onRemoveTemplate());
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

    private void onAddTemplate() {
        List<ZaFridaTemplateCategory> categories = allowedCategories();
        if (categories.isEmpty()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "No template categories available");
            return;
        }

        String[] options = categories.stream().map(Enum::name).toArray(String[]::new);
        String chosen = Messages.showChooseDialog(project, "Select template category", "Add Template", options, options[0], null);
        if (chosen == null) return;

        ZaFridaTemplateCategory category = ZaFridaTemplateCategory.valueOf(chosen);
        String name = Messages.showInputDialog(project, "Template file name (no .js)", "Add Template", null);
        if (StringUtil.isEmptyOrSpaces(name)) return;

        String content = Messages.showMultilineInputDialog(project, "Template JS content", "Add Template", "", null, null);
        if (content == null) return;

        boolean created = templateService.addTemplate(category, name, content);
        if (!created) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Failed to add template. Duplicate name or invalid file.");
            return;
        }

        buildTemplatesUI();
        updateCheckboxState();
    }

    private void onRemoveTemplate() {
        List<ZaFridaTemplate> list = filterTemplatesForPlatform(templateService.all());
        if (list.isEmpty()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "No templates to remove");
            return;
        }

        String[] options = list.stream().map(ZaFridaTemplate::getTitle).toArray(String[]::new);
        String chosen = Messages.showChooseDialog(project, "Select template to remove", "Remove Template", options, options[0], null);
        if (chosen == null) return;

        ZaFridaTemplate target = list.stream()
                .filter(t -> t.getTitle().equals(chosen))
                .findFirst()
                .orElse(null);
        if (target == null) return;

        int confirm = Messages.showYesNoDialog(project,
                "Delete template file?\n" + target.getTitle(),
                "Remove Template",
                null);
        if (confirm != Messages.YES) return;

        boolean deleted = templateService.deleteTemplate(target);
        if (!deleted) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Failed to delete template.");
            return;
        }

        buildTemplatesUI();
        updateCheckboxState();
    }

    private @NotNull List<ZaFridaTemplateCategory> allowedCategories() {
        List<ZaFridaTemplateCategory> categories = new ArrayList<>();
        if (currentPlatform == ZaFridaPlatform.ANDROID) {
            categories.add(ZaFridaTemplateCategory.ANDROID);
        } else if (currentPlatform == ZaFridaPlatform.IOS) {
            categories.add(ZaFridaTemplateCategory.IOS);
        } else {
            categories.add(ZaFridaTemplateCategory.ANDROID);
            categories.add(ZaFridaTemplateCategory.IOS);
        }
        categories.add(ZaFridaTemplateCategory.NATIVE);
        categories.add(ZaFridaTemplateCategory.UTILS);
        return categories;
    }

    private @NotNull List<ZaFridaTemplate> filterTemplatesForPlatform(@NotNull List<ZaFridaTemplate> templates) {
        List<ZaFridaTemplate> filtered = new ArrayList<>();
        for (ZaFridaTemplate t : templates) {
            if (currentPlatform == ZaFridaPlatform.ANDROID && t.getCategory() == ZaFridaTemplateCategory.IOS) continue;
            if (currentPlatform == ZaFridaPlatform.IOS && t.getCategory() == ZaFridaTemplateCategory.ANDROID) continue;
            filtered.add(t);
        }
        return filtered;
    }

    @Override
    public void dispose() {
        // no-op
    }
}
