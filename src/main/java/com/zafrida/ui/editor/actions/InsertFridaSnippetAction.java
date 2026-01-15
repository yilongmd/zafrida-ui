package com.zafrida.ui.editor.actions;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.project.Project;
import org.jetbrains.annotations.NotNull;

/**
 * [编辑器动作基类] Frida 代码片段插入的通用实现。
 * <p>
 * <strong>核心职责：</strong>
 * 1. 定义 IDE 编辑器右键菜单的 Action 行为。
 * 2. <strong>智能填充 (Smart Padding)：</strong> 自动检测光标前后的环境，在必要时自动补充换行符，防止插入的代码与现有代码粘连。
 * 3. <strong>事务管理：</strong> 封装 {@link WriteCommandAction}，确保文件修改操作符合 IntelliJ 线程规范。
 */
public abstract class InsertFridaSnippetAction extends AnAction {
    private final @NotNull String snippet;

    protected InsertFridaSnippetAction(@NotNull String text, @NotNull String snippet) {
        super(text);
        this.snippet = snippet;
    }

    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        Project project = e.getProject();
        Editor editor = e.getData(CommonDataKeys.EDITOR);
        if (project == null || editor == null) return;

        Document document = editor.getDocument();
        if (!document.isWritable()) return;

        int offset = editor.getCaretModel().getOffset();
        String insertion = applyLinePadding(document, offset, snippet);
        WriteCommandAction.runWriteCommandAction(project, () -> document.insertString(offset, insertion));
        editor.getCaretModel().moveToOffset(offset + insertion.length());
    }

    @Override
    public void update(@NotNull AnActionEvent e) {
        Editor editor = e.getData(CommonDataKeys.EDITOR);
        Project project = e.getProject();
        boolean enabled = editor != null && project != null && editor.getDocument().isWritable();
        e.getPresentation().setEnabledAndVisible(enabled);
    }

    private static @NotNull String applyLinePadding(@NotNull Document document, int offset, @NotNull String snippet) {
        CharSequence content = document.getCharsSequence();
        String prefix = needsLeadingNewline(content, offset) ? "\n" : "";
        String suffix = needsTrailingNewline(content, offset) ? "\n" : "";
        return prefix + snippet + suffix;
    }

    private static boolean needsLeadingNewline(@NotNull CharSequence content, int offset) {
        return offset > 0 && content.charAt(offset - 1) != '\n';
    }

    private static boolean needsTrailingNewline(@NotNull CharSequence content, int offset) {
        return offset < content.length() && content.charAt(offset) != '\n';
    }
}
