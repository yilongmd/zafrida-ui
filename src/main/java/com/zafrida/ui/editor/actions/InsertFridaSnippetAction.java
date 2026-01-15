package com.zafrida.ui.editor.actions;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.project.Project;
import org.jetbrains.annotations.NotNull;

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
