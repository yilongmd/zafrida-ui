package com.zafrida.ui.editor.actions;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.fileEditor.FileDocumentManager;
import com.intellij.openapi.project.Project;
import com.zafrida.ui.frida.FridaCliService;
import com.zafrida.ui.util.FridaJsCompatibilityUtil;
import com.zafrida.ui.util.ProjectFileUtil;
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
        if (project == null || editor == null) {
            return;
        }

        Document document = editor.getDocument();
        if (!document.isWritable()) {
            return;
        }

        int offset = editor.getCaretModel().getOffset();
        String rawSnippet = getSnippet(e);
        String convertedSnippet = adaptSnippetForConfiguredFridaVersion(project, rawSnippet);
        String insertion = applyLinePadding(document, offset, convertedSnippet);
        WriteCommandAction.runWriteCommandAction(project, () -> document.insertString(offset, insertion));
        editor.getCaretModel().moveToOffset(offset + insertion.length());
    }

    protected @NotNull String getSnippet(@NotNull AnActionEvent e) {
        return snippet;
    }

    private static @NotNull String adaptSnippetForConfiguredFridaVersion(@NotNull Project project,
                                                                          @NotNull String rawSnippet) {
        FridaCliService fridaCliService =
                ApplicationManager.getApplication().getService(FridaCliService.class);
        boolean frida17OrLater = fridaCliService != null && fridaCliService.isFrida17OrLater(project);
        return FridaJsCompatibilityUtil.adaptForFridaVersion(rawSnippet, frida17OrLater);
    }

    @Override
    public void update(@NotNull AnActionEvent e) {
        Editor editor = e.getData(CommonDataKeys.EDITOR);
        Project project = e.getProject();
        boolean enabled = false;
        if (editor != null && project != null && editor.getDocument().isWritable()) {
            enabled = ProjectFileUtil.isFridaScriptFile(
                    FileDocumentManager.getInstance().getFile(editor.getDocument())
            );
        }
        e.getPresentation().setEnabledAndVisible(enabled);
    }

    private static @NotNull String applyLinePadding(@NotNull Document document, int offset, @NotNull String snippet) {
        CharSequence content = document.getCharsSequence();
        int lineNumber = document.getLineNumber(offset);
        int lineStart = document.getLineStartOffset(lineNumber);
        int lineEnd = document.getLineEndOffset(lineNumber);
        int firstNonWhitespace = findFirstNonWhitespace(content, lineStart, lineEnd);
        String lineIndent = content.subSequence(lineStart, firstNonWhitespace).toString();
        String adjustedSnippet = indentSnippet(snippet, lineIndent);
        StringBuilder builder = new StringBuilder();
        if (shouldAddLeadingNewline(content, offset, firstNonWhitespace)) {
            builder.append('\n');
            builder.append(lineIndent);
        }
        builder.append(adjustedSnippet);
        if (needsTrailingNewline(content, offset)) {
            builder.append('\n');
        }
        return builder.toString();
    }

    private static boolean shouldAddLeadingNewline(@NotNull CharSequence content, int offset, int firstNonWhitespace) {
        if (offset == 0) {
            return false;
        }
        if (content.charAt(offset - 1) == '\n') {
            return false;
        }
        if (offset <= firstNonWhitespace) {
            return false;
        }
        return true;
    }

    private static boolean needsTrailingNewline(@NotNull CharSequence content, int offset) {
        return offset < content.length() && content.charAt(offset) != '\n';
    }

    private static @NotNull String indentSnippet(@NotNull String snippet, @NotNull String lineIndent) {
        if (lineIndent.isEmpty()) {
            return snippet;
        }
        String[] lines = snippet.split("\n", -1);
        if (lines.length <= 1) {
            return snippet;
        }
        StringBuilder builder = new StringBuilder();
        builder.append(lines[0]);
        for (int index = 1; index < lines.length; index++) {
            builder.append('\n');
            if (!lines[index].isEmpty()) {
                builder.append(lineIndent);
            }
            builder.append(lines[index]);
        }
        return builder.toString();
    }

    private static int findFirstNonWhitespace(@NotNull CharSequence content, int lineStart, int lineEnd) {
        int index = lineStart;
        while (index < lineEnd) {
            char current = content.charAt(index);
            if (current != ' ' && current != '\t') {
                break;
            }
            index++;
        }
        return index;
    }
}
