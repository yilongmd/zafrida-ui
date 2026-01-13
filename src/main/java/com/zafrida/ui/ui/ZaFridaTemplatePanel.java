package com.zafrida.ui.ui;

import com.intellij.icons.AllIcons;
import com.intellij.openapi.Disposable;
import com.intellij.openapi.actionSystem.*;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.editor.EditorFactory;
import com.intellij.openapi.editor.EditorSettings;
import com.intellij.openapi.editor.colors.EditorColorsManager;
import com.intellij.openapi.editor.ex.EditorEx;
import com.intellij.openapi.editor.highlighter.EditorHighlighterFactory;
import com.intellij.openapi.fileTypes.FileTypeManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.ui.SimpleToolWindowPanel;
import com.intellij.openapi.ui.Splitter;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.ui.JBColor;
import com.intellij.ui.OnePixelSplitter;
import com.intellij.ui.ScrollPaneFactory;
import com.intellij.ui.components.JBLabel;
import com.intellij.ui.components.JBList;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.util.ui.JBUI;
import com.intellij.util.ui.UIUtil;
import com.zafrida.ui.fridaproject.ZaFridaPlatform;
import com.zafrida.ui.templates.ZaFridaTemplate;
import com.zafrida.ui.templates.ZaFridaTemplateCategory;
import com.zafrida.ui.templates.ZaFridaTemplateService;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import java.awt.*;
import java.util.List;
import java.util.*;
import java.util.stream.Collectors;

public final class ZaFridaTemplatePanel extends JPanel implements Disposable {

    private static final String CATEGORY_FAVORITES = "Favorites";
    private static final String CATEGORY_GENERAL = "General";
    private static final String CATEGORY_CUSTOM = "Custom";

    private final @NotNull Project project;
    private final @NotNull ZaFridaConsolePanel consolePanel;
    private final @NotNull ZaFridaTemplateService templateService;

    private final JBList<String> categoryList;
    private final DefaultListModel<String> categoryModel;
    private final JBList<ZaFridaTemplate> templateList;
    private final DefaultListModel<ZaFridaTemplate> templateModel;

    private final JPanel previewPanel;
    private final JBLabel templateTitleLabel;
    private final JBLabel templateDescLabel;
    private @Nullable Editor previewEditor;
    private @Nullable Document previewDocument;

    private @Nullable ZaFridaPlatform currentPlatform;
    private @Nullable VirtualFile currentScriptFile;

    private final Set<String> favoriteTemplateIds = new HashSet<>();

    public ZaFridaTemplatePanel(@NotNull Project project,
                                 @NotNull ZaFridaConsolePanel consolePanel) {
        super(new BorderLayout());
        this.project = project;
        this.consolePanel = consolePanel;
        this.templateService = new ZaFridaTemplateService(project);

        setBorder(JBUI.Borders.empty());

        // Category list (left narrow column)
        categoryModel = new DefaultListModel<>();
        categoryModel.addElement(CATEGORY_FAVORITES);
        categoryModel.addElement(CATEGORY_GENERAL);
        categoryModel.addElement(CATEGORY_CUSTOM);
        categoryList = new JBList<>(categoryModel);
        categoryList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        categoryList.setCellRenderer(new CategoryListRenderer());
        categoryList.setSelectedIndex(1); // default to General

        JBScrollPane categoryScroll = new JBScrollPane(categoryList);
        categoryScroll.setBorder(JBUI.Borders.customLine(JBColor.border(), 0, 0, 0, 1));
        categoryScroll.setPreferredSize(new Dimension(JBUI.scale(100), 0));
        categoryScroll.setMinimumSize(new Dimension(JBUI.scale(80), 0));

        // Template list (middle column)
        templateModel = new DefaultListModel<>();
        templateList = new JBList<>(templateModel);
        templateList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        templateList.setCellRenderer(new TemplateListRenderer());

        JPanel templateListPanel = new JPanel(new BorderLayout());
        templateListPanel.add(createTemplateToolbar(), BorderLayout.NORTH);
        templateListPanel.add(new JBScrollPane(templateList), BorderLayout.CENTER);

        // Preview panel (right column)
        previewPanel = new JPanel(new BorderLayout());
        previewPanel.setBorder(JBUI.Borders.empty(8));

        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBorder(JBUI.Borders.emptyBottom(8));

        templateTitleLabel = new JBLabel("Select a template");
        templateTitleLabel.setFont(templateTitleLabel.getFont().deriveFont(Font.BOLD, JBUI.scaleFontSize(14)));

        templateDescLabel = new JBLabel("");
        templateDescLabel.setForeground(UIUtil.getContextHelpForeground());

        JPanel titleBlock = new JPanel();
        titleBlock.setLayout(new BoxLayout(titleBlock, BoxLayout.Y_AXIS));
        titleBlock.add(templateTitleLabel);
        titleBlock.add(Box.createVerticalStrut(JBUI.scale(4)));
        titleBlock.add(templateDescLabel);

        JPanel actionPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, JBUI.scale(4), 0));
        JButton insertBtn = new JButton("Insert", AllIcons.Actions.MenuPaste);
        JButton copyBtn = new JButton("Copy", AllIcons.Actions.Copy);
        insertBtn.addActionListener(e -> insertSelectedTemplate());
        copyBtn.addActionListener(e -> copySelectedTemplate());
        actionPanel.add(insertBtn);
        actionPanel.add(copyBtn);

        headerPanel.add(titleBlock, BorderLayout.CENTER);
        headerPanel.add(actionPanel, BorderLayout.EAST);

        previewPanel.add(headerPanel, BorderLayout.NORTH);
        previewPanel.add(createEditorPlaceholder(), BorderLayout.CENTER);

        // Layout with splitters
        OnePixelSplitter leftSplitter = new OnePixelSplitter(false, 0.25f);
        leftSplitter.setFirstComponent(categoryScroll);

        OnePixelSplitter rightSplitter = new OnePixelSplitter(false, 0.35f);
        rightSplitter.setFirstComponent(templateListPanel);
        rightSplitter.setSecondComponent(previewPanel);

        leftSplitter.setSecondComponent(rightSplitter);

        add(leftSplitter, BorderLayout.CENTER);

        // Bind events
        categoryList.addListSelectionListener(this::onCategorySelected);
        templateList.addListSelectionListener(this::onTemplateSelected);

        // Initial load
        refreshTemplateList();
    }

    private JComponent createTemplateToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, JBUI.scale(2), JBUI.scale(2)));
        toolbar.setBorder(JBUI.Borders.customLine(JBColor.border(), 0, 0, 1, 0));

        JButton refreshBtn = createToolButton(AllIcons.Actions.Refresh, "Refresh");
        JButton addBtn = createToolButton(AllIcons.General.Add, "Add template");
        JButton deleteBtn = createToolButton(AllIcons.General.Remove, "Delete template");
        JButton favoriteBtn = createToolButton(AllIcons.Nodes.Favorite, "Toggle favorite");

        refreshBtn.addActionListener(e -> {
            templateService.reload();
            refreshTemplateList();
        });

        addBtn.addActionListener(e -> addNewTemplate());
        deleteBtn.addActionListener(e -> deleteSelectedTemplate());
        favoriteBtn.addActionListener(e -> toggleFavorite());

        toolbar.add(refreshBtn);
        toolbar.add(addBtn);
        toolbar.add(deleteBtn);
        toolbar.add(Box.createHorizontalStrut(JBUI.scale(8)));
        toolbar.add(favoriteBtn);

        return toolbar;
    }

    private JButton createToolButton(Icon icon, String tooltip) {
        JButton btn = new JButton(icon);
        btn.setToolTipText(tooltip);
        btn.setMargin(JBUI.emptyInsets());
        btn.setBorderPainted(false);
        btn.setContentAreaFilled(false);
        btn.setFocusPainted(false);
        Dimension size = new Dimension(JBUI.scale(24), JBUI.scale(24));
        btn.setPreferredSize(size);
        btn.setMinimumSize(size);
        btn.setMaximumSize(size);
        return btn;
    }

    private JComponent createEditorPlaceholder() {
        JPanel placeholder = new JPanel(new BorderLayout());
        placeholder.setBackground(UIUtil.getPanelBackground());
        JBLabel label = new JBLabel("Select a template to preview", SwingConstants.CENTER);
        label.setForeground(UIUtil.getContextHelpForeground());
        placeholder.add(label, BorderLayout.CENTER);
        return placeholder;
    }

    private void onCategorySelected(ListSelectionEvent e) {
        if (e.getValueIsAdjusting()) return;
        refreshTemplateList();
    }

    private void onTemplateSelected(ListSelectionEvent e) {
        if (e.getValueIsAdjusting()) return;
        ZaFridaTemplate selected = templateList.getSelectedValue();
        updatePreview(selected);
    }

    private void refreshTemplateList() {
        templateModel.clear();
        String category = categoryList.getSelectedValue();
        if (category == null) category = CATEGORY_GENERAL;

        List<ZaFridaTemplate> all = templateService.all();
        List<ZaFridaTemplate> filtered;

        switch (category) {
            case CATEGORY_FAVORITES:
                filtered = all.stream()
                        .filter(t -> favoriteTemplateIds.contains(t.getId()))
                        .collect(Collectors.toList());
                break;
            case CATEGORY_CUSTOM:
                filtered = all.stream()
                        .filter(t -> t.getCategory() == ZaFridaTemplateCategory.CUSTOM)
                        .collect(Collectors.toList());
                break;
            case CATEGORY_GENERAL:
            default:
                filtered = all.stream()
                        .filter(t -> t.getCategory() != ZaFridaTemplateCategory.CUSTOM)
                        .collect(Collectors.toList());
                break;
        }

        // Sort: favorites first, then alphabetically
        filtered.sort((a, b) -> {
            boolean aFav = favoriteTemplateIds.contains(a.getId());
            boolean bFav = favoriteTemplateIds.contains(b.getId());
            if (aFav != bFav) return aFav ? -1 : 1;
            return a.getTitle().compareToIgnoreCase(b.getTitle());
        });

        for (ZaFridaTemplate t : filtered) {
            templateModel.addElement(t);
        }

        if (!templateModel.isEmpty()) {
            templateList.setSelectedIndex(0);
        } else {
            updatePreview(null);
        }
    }

    private void updatePreview(@Nullable ZaFridaTemplate template) {
        // Remove old editor
        if (previewEditor != null) {
            previewPanel.remove(previewEditor.getComponent());
            EditorFactory.getInstance().releaseEditor(previewEditor);
            previewEditor = null;
            previewDocument = null;
        }

        if (template == null) {
            templateTitleLabel.setText("Select a template");
            templateDescLabel.setText("");
            previewPanel.add(createEditorPlaceholder(), BorderLayout.CENTER);
            previewPanel.revalidate();
            previewPanel.repaint();
            return;
        }

        templateTitleLabel.setText(template.getTitle());
        templateDescLabel.setText(template.getDescription());

        // Create read-only editor
        previewDocument = EditorFactory.getInstance().createDocument(template.getContent());
        previewEditor = EditorFactory.getInstance().createEditor(
                previewDocument, project, FileTypeManager.getInstance().getFileTypeByExtension("js"), true);

        EditorSettings settings = previewEditor.getSettings();
        settings.setLineNumbersShown(true);
        settings.setFoldingOutlineShown(false);
        settings.setLineMarkerAreaShown(false);
        settings.setGutterIconsShown(false);
        settings.setAdditionalLinesCount(0);
        settings.setAdditionalColumnsCount(0);
        settings.setRightMarginShown(false);

        if (previewEditor instanceof EditorEx) {
            EditorEx ex = (EditorEx) previewEditor;
            ex.setHighlighter(EditorHighlighterFactory.getInstance().createEditorHighlighter(
                    project, FileTypeManager.getInstance().getFileTypeByExtension("js")));
            ex.setColorsScheme(EditorColorsManager.getInstance().getGlobalScheme());
        }

        previewPanel.add(previewEditor.getComponent(), BorderLayout.CENTER);
        previewPanel.revalidate();
        previewPanel.repaint();
    }

    private void insertSelectedTemplate() {
        ZaFridaTemplate t = templateList.getSelectedValue();
        if (t == null) {
            consolePanel.warn("[Template] No template selected");
            return;
        }
        // TODO: Insert into current editor at cursor
        consolePanel.info("[Template] Insert: " + t.getTitle());
        copyToClipboard(t.getContent());
        consolePanel.info("[Template] Copied to clipboard (insert not implemented yet)");
    }

    private void copySelectedTemplate() {
        ZaFridaTemplate t = templateList.getSelectedValue();
        if (t == null) return;
        copyToClipboard(t.getContent());
        consolePanel.info("[Template] Copied: " + t.getTitle());
    }

    private void copyToClipboard(String content) {
        java.awt.datatransfer.StringSelection sel = new java.awt.datatransfer.StringSelection(content);
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, sel);
    }

    private void addNewTemplate() {
        String name = Messages.showInputDialog(project, "Template name:", "Add Template", null);
        if (name == null || name.trim().isEmpty()) return;

        String content = "// " + name + "\n// TODO: Add your Frida script here\n";
        boolean ok = templateService.addTemplate(ZaFridaTemplateCategory.CUSTOM, name, content);
        if (ok) {
            refreshTemplateList();
            consolePanel.info("[Template] Added: " + name);
        } else {
            consolePanel.warn("[Template] Failed to add: " + name);
        }
    }

    private void deleteSelectedTemplate() {
        ZaFridaTemplate t = templateList.getSelectedValue();
        if (t == null) return;

        int result = Messages.showYesNoDialog(
                project,
                "Delete template: " + t.getTitle() + "?",
                "Delete Template",
                Messages.getQuestionIcon()
        );
        if (result != Messages.YES) return;

        boolean ok = templateService.deleteTemplate(t);
        if (ok) {
            favoriteTemplateIds.remove(t.getId());
            refreshTemplateList();
            consolePanel.info("[Template] Deleted: " + t.getTitle());
        }
    }

    private void toggleFavorite() {
        ZaFridaTemplate t = templateList.getSelectedValue();
        if (t == null) return;

        if (favoriteTemplateIds.contains(t.getId())) {
            favoriteTemplateIds.remove(t.getId());
            consolePanel.info("[Template] Unfavorited: " + t.getTitle());
        } else {
            favoriteTemplateIds.add(t.getId());
            consolePanel.info("[Template] Favorited: " + t.getTitle());
        }
        templateList.repaint();

        // Refresh if in favorites view
        if (CATEGORY_FAVORITES.equals(categoryList.getSelectedValue())) {
            refreshTemplateList();
        }
    }

    public void setCurrentPlatform(@Nullable ZaFridaPlatform platform) {
        this.currentPlatform = platform;
    }

    public void setCurrentScriptFile(@Nullable VirtualFile file) {
        this.currentScriptFile = file;
    }

    public @Nullable VirtualFile getCurrentScriptFile() {
        return currentScriptFile;
    }

    @Override
    public void dispose() {
        if (previewEditor != null) {
            EditorFactory.getInstance().releaseEditor(previewEditor);
            previewEditor = null;
        }
    }

    // Renderers
    private static class CategoryListRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                      boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            setBorder(JBUI.Borders.empty(6, 8));

            String cat = (String) value;
            switch (cat) {
                case CATEGORY_FAVORITES:
                    setIcon(AllIcons.Nodes.Favorite);
                    break;
                case CATEGORY_GENERAL:
                    setIcon(AllIcons.Nodes.Template);
                    break;
                case CATEGORY_CUSTOM:
                    setIcon(AllIcons.Nodes.Plugin);
                    break;
            }
            return this;
        }
    }

    private class TemplateListRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                      boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            setBorder(JBUI.Borders.empty(4, 8));

            if (value instanceof ZaFridaTemplate) {
                ZaFridaTemplate t = (ZaFridaTemplate) value;
                setText(t.getTitle());

                if (favoriteTemplateIds.contains(t.getId())) {
                    setIcon(AllIcons.Nodes.Favorite);
                } else {
                    setIcon(AllIcons.FileTypes.JavaScript);
                }
            }
            return this;
        }
    }
}