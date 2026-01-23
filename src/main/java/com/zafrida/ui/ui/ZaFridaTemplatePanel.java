package com.zafrida.ui.ui;

import com.intellij.icons.AllIcons;
import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.editor.EditorFactory;
import com.intellij.openapi.editor.EditorSettings;
import com.intellij.openapi.editor.colors.EditorColorsManager;
import com.intellij.openapi.editor.ex.EditorEx;
import com.intellij.openapi.editor.highlighter.EditorHighlighterFactory;
import com.intellij.openapi.fileEditor.FileDocumentManager;
import com.intellij.openapi.fileTypes.FileTypeManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.ui.CheckBoxList;
import com.intellij.ui.JBColor;
import com.intellij.ui.components.JBTextField;
import com.intellij.ui.OnePixelSplitter;
import com.intellij.ui.components.JBLabel;
import com.intellij.ui.components.JBList;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.DocumentAdapter;
import com.intellij.util.ui.JBUI;
import com.intellij.util.ui.UIUtil;
import com.zafrida.ui.fridaproject.ZaFridaPlatform;
import com.zafrida.ui.templates.ZaFridaTemplate;
import com.zafrida.ui.templates.ZaFridaTemplateCategory;
import com.zafrida.ui.templates.ZaFridaTemplateService;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.ListSelectionEvent;
import java.awt.*;
import java.util.List;
import java.util.*;
import java.util.stream.Collectors;

/**
 * [UI组件] 模板管理面板（复选框驱动开发核心）。
 * <p>
 * <strong>交互逻辑：</strong>
 * 用户通过勾选/取消勾选左侧的 Hook 模板，直接控制右侧编辑器中的代码块。
 * <p>
 * <strong>实现原理：</strong>
 * 依赖 {@link #onTemplateCheckboxChanged} 方法：
 * <ul>
 * <li>选中 -> 插入代码 或 取消注释 (Uncomment)。</li>
 * <li>取消 -> 将对应 Marker 之间的代码每行添加 `//` 前缀 (Comment)，而非物理删除。</li>
 * </ul>
 * 这种机制保证了用户对模板的手动修改不会因为开关操作而丢失。
 */
public final class ZaFridaTemplatePanel extends JPanel implements Disposable {

    /** 收藏分类名称 */
    private static final String CATEGORY_FAVORITES = "Favorites";
    /** Android 分类名称 */
    private static final String CATEGORY_ANDROID = "Android";
    /** iOS 分类名称 */
    private static final String CATEGORY_IOS = "iOS";
    /** 自定义分类名称 */
    private static final String CATEGORY_CUSTOM = "Custom";

    // 模板标记
    /** 模板块开始标记前缀 */
    private static final String TEMPLATE_START_PREFIX = "// ===== [ZaFrida Template Start: ";
    /** 模板块结束标记前缀 */
    private static final String TEMPLATE_END_PREFIX = "// ===== [ZaFrida Template End: ";
    /** 模板块标记后缀 */
    private static final String TEMPLATE_MARKER_SUFFIX = "] =====";

    /** IDE 项目实例 */
    private final @NotNull Project project;
    /** 控制台面板 */
    private final @NotNull ZaFridaConsolePanel consolePanel;
    /** 模板服务 */
    private final @NotNull ZaFridaTemplateService templateService;

    /** 分类列表组件 */
    private final JBList<String> categoryList;
    /** 分类列表模型 */
    private final DefaultListModel<String> categoryModel;

    /** 模板复选列表 */
    private final CheckBoxList<ZaFridaTemplate> templateCheckBoxList;
    /** 模板过滤输入框 */
    private final JBTextField templateFilterField = new JBTextField();

    /** 预览面板 */
    private final JPanel previewPanel;
    /** 模板标题标签 */
    private final JBLabel templateTitleLabel;
    /** 模板描述标签 */
    private final JBLabel templateDescLabel;
    /** 预览编辑器 */
    private @Nullable Editor previewEditor;
    /** 预览文档 */
    private @Nullable Document previewDocument;

    /** 当前平台 */
    private @Nullable ZaFridaPlatform currentPlatform;
    /** 当前脚本文件 */
    private @Nullable VirtualFile currentScriptFile;

    /** 收藏模板 ID 集合 */
    private final Set<String> favoriteTemplateIds = new HashSet<>();
    /** 复选框更新保护开关 */
    private boolean isUpdatingCheckboxes = false;

    /**
     * 构造函数。
     * @param project 当前 IDE 项目
     * @param consolePanel 控制台面板
     */
    public ZaFridaTemplatePanel(@NotNull Project project,
                                @NotNull ZaFridaConsolePanel consolePanel) {
        super(new BorderLayout());
        this.project = project;
        this.consolePanel = consolePanel;
        this.templateService = new ZaFridaTemplateService(project);

        setBorder(JBUI.Borders.empty());

        // Category list (left narrow column)
        // 分类列表（左侧窄列）
        categoryModel = new DefaultListModel<>();
        categoryModel.addElement(CATEGORY_FAVORITES);
        categoryModel.addElement(CATEGORY_ANDROID);
        categoryModel.addElement(CATEGORY_IOS);
        categoryModel.addElement(CATEGORY_CUSTOM);
        categoryList = new JBList<>(categoryModel);
        categoryList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        categoryList.setCellRenderer(new CategoryListRenderer());
        categoryList.setSelectedIndex(1); // 默认选中 Android

        JBScrollPane categoryScroll = new JBScrollPane(categoryList);
        categoryScroll.setBorder(JBUI.Borders.customLine(JBColor.border(), 0, 0, 0, 1));

        // Template checkbox list (middle column)
        // 模板复选列表（中间列）
        templateCheckBoxList = new CheckBoxList<>();
        templateCheckBoxList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        JPanel templateListPanel = new JPanel(new BorderLayout());
        templateListPanel.add(createTemplateToolbar(), BorderLayout.NORTH);
        templateListPanel.add(new JBScrollPane(templateCheckBoxList), BorderLayout.CENTER);
        templateListPanel.add(createSelectionActionPanel(), BorderLayout.SOUTH);

        // Preview panel (right column)
        // 预览面板（右侧列）
        previewPanel = new JPanel(new BorderLayout());
        previewPanel.setBorder(JBUI.Borders.empty(4));

        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBorder(JBUI.Borders.emptyBottom(4));

        templateTitleLabel = new JBLabel("Select a template");
        templateTitleLabel.setFont(templateTitleLabel.getFont().deriveFont(Font.BOLD, JBUI.scaleFontSize(12)));

        templateDescLabel = new JBLabel("");
        templateDescLabel.setForeground(UIUtil.getContextHelpForeground());
        templateDescLabel.setFont(templateDescLabel.getFont().deriveFont(JBUI.scaleFontSize(10)));

        JPanel titleBlock = new JPanel();
        titleBlock.setLayout(new BoxLayout(titleBlock, BoxLayout.Y_AXIS));
        titleBlock.add(templateTitleLabel);
        titleBlock.add(Box.createVerticalStrut(JBUI.scale(2)));
        titleBlock.add(templateDescLabel);

        JPanel buttonsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, JBUI.scale(2), 0));
        JButton copyBtn = createToolButton(AllIcons.Actions.Copy, "Copy to clipboard");
        JButton openFolderBtn = createToolButton(AllIcons.Actions.MenuOpen, "Open templates folder");
        copyBtn.addActionListener(e -> copySelectedTemplate());
        openFolderBtn.addActionListener(e -> openTemplatesFolder());
        buttonsPanel.add(copyBtn);
        buttonsPanel.add(openFolderBtn);

        headerPanel.add(titleBlock, BorderLayout.CENTER);
        headerPanel.add(buttonsPanel, BorderLayout.EAST);

        previewPanel.add(headerPanel, BorderLayout.NORTH);
        previewPanel.add(createEditorPlaceholder(), BorderLayout.CENTER);

        // Layout with splitters
        // 使用分隔条布局
        OnePixelSplitter leftSplitter = new OnePixelSplitter(false, 0.12f);
        leftSplitter.setFirstComponent(categoryScroll);

        OnePixelSplitter rightSplitter = new OnePixelSplitter(false, 0.35f);
        rightSplitter.setFirstComponent(templateListPanel);
        rightSplitter.setSecondComponent(previewPanel);
        rightSplitter.setHonorComponentsMinimumSize(false);

        leftSplitter.setSecondComponent(rightSplitter);
        leftSplitter.setHonorComponentsMinimumSize(false);

        add(leftSplitter, BorderLayout.CENTER);

        // Bind events
        // 绑定事件
        categoryList.addListSelectionListener(this::onCategorySelected);
        templateCheckBoxList.addListSelectionListener(this::onTemplateSelected);

        templateCheckBoxList.setCheckBoxListListener((index, selected) -> {
            if (isUpdatingCheckboxes) return;
            ZaFridaTemplate template = templateCheckBoxList.getItemAt(index);
            if (template != null) {
                onTemplateCheckboxChanged(template, selected);
            }
        });

        // Initial load
        // 初始化加载
        refreshTemplateList();
    }

    /**
     * 打开模板目录。
     */
    private void openTemplatesFolder() {
        try {
            java.awt.Desktop.getDesktop().open(templateService.getUserTemplatesRoot().toFile());
        } catch (Exception e) {
            consolePanel.error("[Template] Failed to open folder: " + e.getMessage());
        }
    }

    /**
     * 处理模板勾选状态变化。
     * @param template 模板对象
     * @param selected 是否选中
     */
    private void onTemplateCheckboxChanged(@NotNull ZaFridaTemplate template, boolean selected) {
        if (currentScriptFile == null) {
            consolePanel.warn("[Template] No script file selected. Please select a script file first.");
            revertCheckboxState(template, !selected);
            return;
        }

        Document document = FileDocumentManager.getInstance().getDocument(currentScriptFile);
        if (document == null) {
            consolePanel.warn("[Template] Cannot access document for: " + currentScriptFile.getName());
            revertCheckboxState(template, !selected);
            return;
        }

        String content = document.getText();
        String templateId = template.getId();
        String startMarker = TEMPLATE_START_PREFIX + templateId + TEMPLATE_MARKER_SUFFIX;
        String endMarker = TEMPLATE_END_PREFIX + templateId + TEMPLATE_MARKER_SUFFIX;

        if (selected) {
            if (content.contains(startMarker)) {
                // 已存在，取消注释
                uncommentTemplate(document, templateId, startMarker, endMarker);
                consolePanel.info("[Template] Uncommented: " + template.getTitle());
            } else {
                // 不存在，插入
                insertTemplate(document, template, startMarker, endMarker);
                consolePanel.info("[Template] Inserted: " + template.getTitle());
            }
        } else {
            if (content.contains(startMarker)) {
                // 存在，注释掉
                commentTemplate(document, templateId, startMarker, endMarker);
                consolePanel.info("[Template] Commented: " + template.getTitle());
            }
        }
    }

    /**
     * 回滚复选框状态（避免递归触发事件）。
     * @param template 模板对象
     * @param state 目标状态
     */
    private void revertCheckboxState(@NotNull ZaFridaTemplate template, boolean state) {
        isUpdatingCheckboxes = true;
        try {
            templateCheckBoxList.setItemSelected(template, state);
        } finally {
            isUpdatingCheckboxes = false;
        }
    }

    /**
     * 插入模板内容到脚本尾部。
     * @param document 文档对象
     * @param template 模板对象
     * @param startMarker 开始标记
     * @param endMarker 结束标记
     */
    private void insertTemplate(@NotNull Document document, @NotNull ZaFridaTemplate template,
                                String startMarker, String endMarker) {
        WriteCommandAction.runWriteCommandAction(project, () -> {
            String content = document.getText();
            StringBuilder sb = new StringBuilder();

            if (!content.endsWith("\n")) {
                sb.append("\n");
            }
            sb.append("\n");
            sb.append(startMarker).append("\n");
            sb.append(template.getContent());
            if (!template.getContent().endsWith("\n")) {
                sb.append("\n");
            }
            sb.append(endMarker).append("\n");

            document.insertString(document.getTextLength(), sb.toString());
        });
    }

    /**
     * 将模板块注释掉。
     * @param document 文档对象
     * @param templateId 模板 ID
     * @param startMarker 开始标记
     * @param endMarker 结束标记
     */
    private void commentTemplate(@NotNull Document document, String templateId,
                                 String startMarker, String endMarker) {
        WriteCommandAction.runWriteCommandAction(project, () -> {
            String content = document.getText();
            int startIdx = content.indexOf(startMarker);
            int endIdx = content.indexOf(endMarker);

            if (startIdx == -1 || endIdx == -1 || endIdx <= startIdx) return;

            int contentStart = content.indexOf('\n', startIdx) + 1;
            int contentEnd = endIdx;

            if (contentStart >= contentEnd) return;

            String templateContent = content.substring(contentStart, contentEnd);
            // 移除末尾多余的换行符，只保留一个
            while (templateContent.endsWith("\n\n")) {
                templateContent = templateContent.substring(0, templateContent.length() - 1);
            }

            String[] lines = templateContent.split("\n", -1);
            StringBuilder commented = new StringBuilder();

            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                // 跳过最后的空行
                if (i == lines.length - 1 && line.isEmpty()) {
                    continue;
                }
                // 所有非空行都添加注释前缀，不管是否已有 //
                if (!line.isEmpty()) {
                    commented.append("// ").append(line).append("\n");
                } else {
                    commented.append("//\n");
                }
            }

            document.replaceString(contentStart, contentEnd, commented.toString());
        });
    }

    /**
     * 取消模板块注释。
     * @param document 文档对象
     * @param templateId 模板 ID
     * @param startMarker 开始标记
     * @param endMarker 结束标记
     */
    private void uncommentTemplate(@NotNull Document document, String templateId,
                                   String startMarker, String endMarker) {
        WriteCommandAction.runWriteCommandAction(project, () -> {
            String content = document.getText();
            int startIdx = content.indexOf(startMarker);
            int endIdx = content.indexOf(endMarker);

            if (startIdx == -1 || endIdx == -1 || endIdx <= startIdx) return;

            int contentStart = content.indexOf('\n', startIdx) + 1;
            int contentEnd = endIdx;

            if (contentStart >= contentEnd) return;

            String templateContent = content.substring(contentStart, contentEnd);
            // 移除末尾多余的换行符
            while (templateContent.endsWith("\n\n")) {
                templateContent = templateContent.substring(0, templateContent.length() - 1);
            }

            String[] lines = templateContent.split("\n", -1);
            StringBuilder uncommented = new StringBuilder();

            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                // 跳过最后的空行
                if (i == lines.length - 1 && line.isEmpty()) {
                    continue;
                }
                // 只移除一层 "// " 前缀
                if (line.startsWith("// ")) {
                    uncommented.append(line.substring(3)).append("\n");
                } else if (line.equals("//")) {
                    uncommented.append("\n");
                } else if (line.startsWith("//")) {
                    uncommented.append(line.substring(2)).append("\n");
                } else {
                    uncommented.append(line).append("\n");
                }
            }

            document.replaceString(contentStart, contentEnd, uncommented.toString());
        });
    }

    /**
     * 同步复选框状态与脚本内容。
     */
    public void syncCheckboxStatesWithScript() {
        if (currentScriptFile == null) return;

        Document document = FileDocumentManager.getInstance().getDocument(currentScriptFile);
        if (document == null) return;

        String content = document.getText();

        isUpdatingCheckboxes = true;
        try {
            for (int i = 0; i < templateCheckBoxList.getItemsCount(); i++) {
                ZaFridaTemplate template = templateCheckBoxList.getItemAt(i);
                if (template == null) continue;

                String startMarker = TEMPLATE_START_PREFIX + template.getId() + TEMPLATE_MARKER_SUFFIX;
                boolean exists = content.contains(startMarker);
                boolean isCommented = false;

                if (exists) {
                    int startIdx = content.indexOf(startMarker);
                    int endMarkerIdx = content.indexOf(TEMPLATE_END_PREFIX + template.getId());
                    if (startIdx != -1 && endMarkerIdx > startIdx) {
                        int contentStart = content.indexOf('\n', startIdx) + 1;
                        String templateContent = content.substring(contentStart, endMarkerIdx);
                        String[] lines = templateContent.split("\n");
                        int commentedLines = 0;
                        int totalLines = 0;
                        for (String line : lines) {
                            if (!line.trim().isEmpty()) {
                                totalLines++;
                                if (line.trim().startsWith("//")) {
                                    commentedLines++;
                                }
                            }
                        }
                        isCommented = totalLines > 0 && commentedLines == totalLines;
                    }
                }

                templateCheckBoxList.setItemSelected(template, exists && !isCommented);
            }
        } finally {
            isUpdatingCheckboxes = false;
        }
    }

    /**
     * 创建模板工具栏。
     * @return 工具栏组件
     */
    private JComponent createTemplateToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, JBUI.scale(2), JBUI.scale(2)));
        toolbar.setBorder(JBUI.Borders.customLine(JBColor.border(), 0, 0, 1, 0));

        JButton refreshBtn = createToolButton(AllIcons.Actions.Refresh, "Refresh templates");
        JButton addBtn = createToolButton(AllIcons.General.Add, "Add custom template");
        JButton deleteBtn = createToolButton(AllIcons.General.Remove, "Delete custom template");
        JButton favoriteBtn = createToolButton(AllIcons.Nodes.Favorite, "Toggle favorite");

        refreshBtn.addActionListener(e -> {
            templateService.reload();
            refreshTemplateList();
            syncCheckboxStatesWithScript();
            consolePanel.info("[Template] Templates reloaded");
        });

        addBtn.addActionListener(e -> addNewTemplate());
        deleteBtn.addActionListener(e -> deleteSelectedTemplate());
        favoriteBtn.addActionListener(e -> toggleFavorite());

        toolbar.add(refreshBtn);
        toolbar.add(addBtn);
        toolbar.add(deleteBtn);
        toolbar.add(Box.createHorizontalStrut(JBUI.scale(4)));
        toolbar.add(favoriteBtn);
        toolbar.add(Box.createHorizontalStrut(JBUI.scale(6)));

        toolbar.add(new JBLabel("Filter:"));
        templateFilterField.setToolTipText("Filter by template title or description");
        templateFilterField.setPreferredSize(new Dimension(JBUI.scale(160), templateFilterField.getPreferredSize().height));
        templateFilterField.getDocument().addDocumentListener(new DocumentAdapter() {
            @Override
            protected void textChanged(@NotNull DocumentEvent e) {
                refreshTemplateList();
                syncCheckboxStatesWithScript();
            }
        });
        toolbar.add(templateFilterField);

        return toolbar;
    }

    /**
     * 创建选择操作面板。
     * @return 面板
     */
    private JPanel createSelectionActionPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, JBUI.scale(4), JBUI.scale(4)));
        panel.setBorder(JBUI.Borders.customLine(JBColor.border(), 1, 0, 0, 0));

        JButton copySelectedBtn = new JButton("Copy Selected");
        copySelectedBtn.setIcon(AllIcons.Actions.Copy);
        copySelectedBtn.setMargin(JBUI.insets(2, 6));
        copySelectedBtn.addActionListener(e -> copyAllSelected());

        JLabel hintLabel = new JBLabel("✓ insert/uncomment, ✗ comment");
        hintLabel.setForeground(UIUtil.getContextHelpForeground());
        hintLabel.setFont(hintLabel.getFont().deriveFont(JBUI.scaleFontSize(10)));

        panel.add(copySelectedBtn);
        panel.add(Box.createHorizontalStrut(JBUI.scale(8)));
        panel.add(hintLabel);

        return panel;
    }

    /**
     * 创建无边框图标按钮。
     * @param icon 图标
     * @param tooltip 提示文本
     * @return 按钮
     */
    private JButton createToolButton(Icon icon, String tooltip) {
        JButton btn = new JButton(icon);
        btn.setToolTipText(tooltip);
        btn.setMargin(JBUI.emptyInsets());
        btn.setBorderPainted(false);
        btn.setContentAreaFilled(false);
        btn.setFocusPainted(false);
        Dimension size = new Dimension(JBUI.scale(22), JBUI.scale(22));
        btn.setPreferredSize(size);
        btn.setMinimumSize(size);
        btn.setMaximumSize(size);
        return btn;
    }

    /**
     * 创建编辑器占位组件。
     * @return 占位组件
     */
    private JComponent createEditorPlaceholder() {
        JPanel placeholder = new JPanel(new BorderLayout());
        placeholder.setBackground(UIUtil.getPanelBackground());
        JBLabel label = new JBLabel("Select a template to preview", SwingConstants.CENTER);
        label.setForeground(UIUtil.getContextHelpForeground());
        placeholder.add(label, BorderLayout.CENTER);
        return placeholder;
    }

    /**
     * 分类选择事件处理。
     * @param e 事件
     */
    private void onCategorySelected(ListSelectionEvent e) {
        if (e.getValueIsAdjusting()) return;
        refreshTemplateList();
        syncCheckboxStatesWithScript();
    }

    /**
     * 模板选择事件处理。
     * @param e 事件
     */
    private void onTemplateSelected(ListSelectionEvent e) {
        if (e.getValueIsAdjusting()) return;
        int index = templateCheckBoxList.getSelectedIndex();
        if (index >= 0) {
            ZaFridaTemplate selected = templateCheckBoxList.getItemAt(index);
            updatePreview(selected);
        } else {
            updatePreview(null);
        }
    }

    /**
     * 刷新模板列表。
     */
    private void refreshTemplateList() {
        isUpdatingCheckboxes = true;
        try {
            templateCheckBoxList.clear();

            String category = categoryList.getSelectedValue();
            if (category == null) category = CATEGORY_ANDROID;

            List<ZaFridaTemplate> all = templateService.all();
            List<ZaFridaTemplate> filtered;

            switch (category) {
                case CATEGORY_FAVORITES:
                    filtered = all.stream()
                            .filter(t -> favoriteTemplateIds.contains(t.getId()))
                            .collect(Collectors.toList());
                    break;
                case CATEGORY_ANDROID:
                    filtered = all.stream()
                            .filter(t -> t.getCategory() == ZaFridaTemplateCategory.ANDROID)
                            .collect(Collectors.toList());
                    break;
                case CATEGORY_IOS:
                    filtered = all.stream()
                            .filter(t -> t.getCategory() == ZaFridaTemplateCategory.IOS)
                            .collect(Collectors.toList());
                    break;
                case CATEGORY_CUSTOM:
                    filtered = all.stream()
                            .filter(t -> t.getCategory() == ZaFridaTemplateCategory.CUSTOM)
                            .collect(Collectors.toList());
                    break;
                default:
                    filtered = all;
            }

            String filterText = templateFilterField.getText().trim();
            if (!filterText.isEmpty()) {
                String needle = filterText.toLowerCase(Locale.ROOT);
                filtered = filtered.stream()
                        .filter(template -> matchesFilter(template, needle))
                        .collect(Collectors.toList());
            }

            // Sort: favorites first, then alphabetically
            // 排序：收藏优先，其次按名称排序
            filtered.sort((a, b) -> {
                boolean aFav = favoriteTemplateIds.contains(a.getId());
                boolean bFav = favoriteTemplateIds.contains(b.getId());
                if (aFav != bFav) return aFav ? -1 : 1;
                return a.getTitle().compareToIgnoreCase(b.getTitle());
            });

            for (ZaFridaTemplate t : filtered) {
                templateCheckBoxList.addItem(t, t.getTitle(), false);
            }

            if (templateCheckBoxList.getItemsCount() > 0) {
                templateCheckBoxList.setSelectedIndex(0);
            } else {
                updatePreview(null);
            }
        } finally {
            isUpdatingCheckboxes = false;
        }
    }

    /**
     * 判断模板是否匹配过滤条件。
     * @param template 模板对象
     * @param needle 过滤关键字
     * @return true 表示匹配
     */
    private boolean matchesFilter(@NotNull ZaFridaTemplate template, @NotNull String needle) {
        String title = template.getTitle();
        if (title != null && title.toLowerCase(Locale.ROOT).contains(needle)) {
            return true;
        }
        String desc = template.getDescription();
        return desc != null && desc.toLowerCase(Locale.ROOT).contains(needle);
    }

    /**
     * 更新预览面板。
     * @param template 目标模板
     */
    private void updatePreview(@Nullable ZaFridaTemplate template) {
        // 清除旧的编辑器组件（保留header）
        Component[] components = previewPanel.getComponents();
        for (int i = components.length - 1; i > 0; i--) {
            previewPanel.remove(components[i]);
        }

        if (previewEditor != null) {
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
        String desc = template.getDescription();
        if (desc != null && desc.length() > 80) {
            desc = desc.substring(0, 77) + "...";
        }
        templateDescLabel.setText(desc != null ? desc : "");

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
        settings.setCaretRowShown(false);
        settings.setUseSoftWraps(false);

        if (previewEditor instanceof EditorEx) {
            EditorEx ex = (EditorEx) previewEditor;
            ex.setHighlighter(EditorHighlighterFactory.getInstance().createEditorHighlighter(
                    project, FileTypeManager.getInstance().getFileTypeByExtension("js")));
            ex.setColorsScheme(EditorColorsManager.getInstance().getGlobalScheme());
            ex.setVerticalScrollbarVisible(true);
            ex.setHorizontalScrollbarVisible(true);
        }

        previewPanel.add(previewEditor.getComponent(), BorderLayout.CENTER);
        previewPanel.revalidate();
        previewPanel.repaint();
    }

    /**
     * 复制当前选中模板内容。
     */
    private void copySelectedTemplate() {
        int index = templateCheckBoxList.getSelectedIndex();
        if (index < 0) return;
        ZaFridaTemplate t = templateCheckBoxList.getItemAt(index);
        if (t == null) return;
        copyToClipboard(t.getContent());
        consolePanel.info("[Template] Copied: " + t.getTitle());
    }

    /**
     * 复制所有已选模板内容。
     */
    private void copyAllSelected() {
        List<ZaFridaTemplate> selected = new ArrayList<>();
        for (int i = 0; i < templateCheckBoxList.getItemsCount(); i++) {
            if (templateCheckBoxList.isItemSelected(i)) {
                ZaFridaTemplate t = templateCheckBoxList.getItemAt(i);
                if (t != null) selected.add(t);
            }
        }

        if (selected.isEmpty()) {
            consolePanel.warn("[Template] No templates selected");
            return;
        }

        StringBuilder sb = new StringBuilder();
        for (ZaFridaTemplate t : selected) {
            sb.append(TEMPLATE_START_PREFIX).append(t.getId()).append(TEMPLATE_MARKER_SUFFIX).append("\n");
            sb.append(t.getContent());
            if (!t.getContent().endsWith("\n")) sb.append("\n");
            sb.append(TEMPLATE_END_PREFIX).append(t.getId()).append(TEMPLATE_MARKER_SUFFIX).append("\n\n");
        }

        copyToClipboard(sb.toString().trim());
        consolePanel.info("[Template] Copied " + selected.size() + " template(s)");
    }

    /**
     * 写入系统剪贴板。
     * @param content 文本内容
     */
    private void copyToClipboard(String content) {
        java.awt.datatransfer.StringSelection sel = new java.awt.datatransfer.StringSelection(content);
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, sel);
    }

    /**
     * 添加新的自定义模板。
     */
    private void addNewTemplate() {
        AddTemplateDialog dialog = new AddTemplateDialog(project);
        if (dialog.showAndGet()) {
            String name = dialog.getTemplateName();
            String content = dialog.getTemplateContent();

            boolean ok = templateService.addTemplate(ZaFridaTemplateCategory.CUSTOM, name, content);
            if (ok) {
                // 切换到 Custom 分类
                categoryList.setSelectedValue(CATEGORY_CUSTOM, true);
                refreshTemplateList();
                consolePanel.info("[Template] Added: " + name);
            } else {
                consolePanel.error("[Template] Failed to add: " + name);
            }
        }
    }

    /**
     * 删除当前选中的模板。
     */
    private void deleteSelectedTemplate() {
        int index = templateCheckBoxList.getSelectedIndex();
        if (index < 0) return;
        ZaFridaTemplate t = templateCheckBoxList.getItemAt(index);
        if (t == null) return;

        if (!t.isCustom()) {
            Messages.showWarningDialog(project,
                    "Only custom templates can be deleted.\nBuilt-in templates are read-only.",
                    "Cannot Delete");
            return;
        }

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

    /**
     * 切换模板收藏状态。
     */
    private void toggleFavorite() {
        int index = templateCheckBoxList.getSelectedIndex();
        if (index < 0) return;
        ZaFridaTemplate t = templateCheckBoxList.getItemAt(index);
        if (t == null) return;

        if (favoriteTemplateIds.contains(t.getId())) {
            favoriteTemplateIds.remove(t.getId());
            consolePanel.info("[Template] Unfavorited: " + t.getTitle());
        } else {
            favoriteTemplateIds.add(t.getId());
            consolePanel.info("[Template] Favorited: " + t.getTitle());
        }

        if (CATEGORY_FAVORITES.equals(categoryList.getSelectedValue())) {
            refreshTemplateList();
        }
    }

    /**
     * 设置当前平台（用于模板过滤）。
     * @param platform 平台
     */
    public void setCurrentPlatform(@Nullable ZaFridaPlatform platform) {
        this.currentPlatform = platform;
    }

    /**
     * 设置当前脚本文件。
     * @param file 脚本文件
     */
    public void setCurrentScriptFile(@Nullable VirtualFile file) {
        this.currentScriptFile = file;
        ApplicationManager.getApplication().invokeLater(this::syncCheckboxStatesWithScript);
    }

    /**
     * 获取当前脚本文件。
     * @return 脚本文件或 null
     */
    public @Nullable VirtualFile getCurrentScriptFile() {
        return currentScriptFile;
    }

    /**
     * 释放资源。
     */
    @Override
    public void dispose() {
        if (previewEditor != null) {
            EditorFactory.getInstance().releaseEditor(previewEditor);
            previewEditor = null;
        }
    }

    /**
     * 分类列表渲染器。
     */
    private static class CategoryListRenderer extends DefaultListCellRenderer {
        /**
         * 渲染分类列表项。
         */
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                      boolean isSelected, boolean cellHasFocus) {
            super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            setBorder(JBUI.Borders.empty(4, 6));

            String cat = (String) value;
            switch (cat) {
                case CATEGORY_FAVORITES:
                    setIcon(AllIcons.Nodes.Favorite);
                    break;
                case CATEGORY_ANDROID:
                    setIcon(AllIcons.Nodes.Module);
                    break;
                case CATEGORY_IOS:
                    setIcon(AllIcons.Nodes.Module);
                    break;
                case CATEGORY_CUSTOM:
                    setIcon(AllIcons.Nodes.Plugin);
                    break;
            }
            return this;
        }
    }
}
