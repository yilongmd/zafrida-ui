package com.zafrida.ui.templates;

import com.intellij.openapi.editor.Document;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * [工具类] 脚本内容操作引擎。
 * <p>
 * <strong>职责：</strong>
 * 负责在 Document 中查找、插入、注释或反注释特定的模板代码块。
 * <p>
 * <strong>Marker 协议：</strong>
 * 代码块必须包裹在以下标记中，AI 生成代码时严禁修改此格式：
 * <pre>
 * //== ZAFrida:TEMPLATE:{id}:BEGIN ==
 * ... content ...
 * //== ZAFrida:TEMPLATE:{id}:END ==
 * </pre>
 */
public final class TemplateScriptManipulator {

    private static final String TEMPLATES_BEGIN = "//== ZAFrida:TEMPLATES:BEGIN ==";
    private static final String TEMPLATES_END = "//== ZAFrida:TEMPLATES:END ==";

    private TemplateScriptManipulator() {
    }

    private static @NotNull String beginMarker(@NotNull String id) {
        return "//== ZAFrida:TEMPLATE:" + id + ":BEGIN ==";
    }

    private static @NotNull String endMarker(@NotNull String id) {
        return "//== ZAFrida:TEMPLATE:" + id + ":END ==";
    }

    /**
     * @return Boolean.TRUE  -> template block exists and is enabled
     *         Boolean.FALSE -> template block exists but is disabled (wrapped by block comments)
     *         null          -> template block does not exist
     */
    public static @Nullable Boolean isTemplateEnabled(@NotNull String text, @NotNull String templateId) {
        String b = beginMarker(templateId);
        String e = endMarker(templateId);

        int bi = text.indexOf(b);
        if (bi < 0) return null;
        int ei = text.indexOf(e, bi + b.length());
        if (ei < 0) return null;

        String between = text.substring(bi + b.length(), ei);
        String[] lines = between.split("\\R");
        for (String line : lines) {
            String t = line.trim();
            if (t.isEmpty()) continue;
            return !t.equals("/*");
        }
        return Boolean.TRUE;
    }

    public static void ensureTemplatesSection(@NotNull Document document) {
        String text = document.getText();
        if (text.contains(TEMPLATES_BEGIN) && text.contains(TEMPLATES_END)) {
            return;
        }
        String appendix = "\n" + TEMPLATES_BEGIN + "\n" + TEMPLATES_END + "\n";
        document.insertString(document.getTextLength(), appendix);
    }

    public static void setTemplateEnabled(@NotNull Document document, @NotNull ZaFridaTemplate template, boolean enabled) {
        ensureTemplatesSection(document);

        String id = template.getId();
        String b = beginMarker(id);
        String e = endMarker(id);

        String text = document.getText();
        int bi = text.indexOf(b);
        int ei = bi >= 0 ? text.indexOf(e, bi + b.length()) : -1;

        if (bi < 0 || ei < 0) {
            // insert new block before templates end marker
            int endIdx = document.getText().indexOf(TEMPLATES_END);
            int insertOffset = endIdx >= 0 ? endIdx : document.getTextLength();
            document.insertString(insertOffset, buildBlock(template, enabled));
            return;
        }

        toggleExistingBlock(document, id, enabled);
    }

    private static @NotNull String buildBlock(@NotNull ZaFridaTemplate template, boolean enabled) {
        String b = beginMarker(template.getId());
        String e = endMarker(template.getId());
        String content = template.getContent().stripTrailing();
        if (enabled) {
            return "\n" + b + "\n" + content + "\n" + e + "\n";
        }
        return "\n" + b + "\n/*\n" + content + "\n*/\n" + e + "\n";
    }

    private static void toggleExistingBlock(@NotNull Document document, @NotNull String templateId, boolean enabled) {
        String b = beginMarker(templateId);
        String e = endMarker(templateId);

        String text = document.getText();
        int bi = text.indexOf(b);
        int ei = text.indexOf(e, bi + b.length());
        if (bi < 0 || ei < 0) return;

        int beginLine = document.getLineNumber(bi);
        int endLine = document.getLineNumber(ei);

        Integer first = findFirstNonEmptyLine(document, beginLine + 1, endLine - 1);
        Integer last = findLastNonEmptyLine(document, beginLine + 1, endLine - 1);

        boolean hasStart = first != null && getLineText(document, first).trim().equals("/*");
        boolean hasEnd = last != null && getLineText(document, last).trim().equals("*/");

        if (enabled) {
            // remove wrappers, bottom first then top
            if (hasEnd && last != null) removeLine(document, last);
            if (hasStart && first != null) removeLine(document, first);
            return;
        }

        // add wrappers, bottom first then top
        if (!hasEnd) {
            // end marker line may change after insertions, but inserting bottom first avoids recompute issues
            int endMarkerOffset = document.getText().indexOf(e);
            if (endMarkerOffset >= 0) {
                int endMarkerLine = document.getLineNumber(endMarkerOffset);
                int insertBeforeEndMarker = document.getLineStartOffset(endMarkerLine);
                document.insertString(insertBeforeEndMarker, "*/\n");
            }
        }

        if (!hasStart) {
            int afterBegin = offsetAfterLine(document, beginLine);
            document.insertString(afterBegin, "/*\n");
        }
    }

    private static @Nullable Integer findFirstNonEmptyLine(@NotNull Document document, int from, int to) {
        if (from > to) return null;
        for (int i = from; i <= to; i++) {
            if (!getLineText(document, i).trim().isEmpty()) return i;
        }
        return null;
    }

    private static @Nullable Integer findLastNonEmptyLine(@NotNull Document document, int from, int to) {
        if (from > to) return null;
        for (int i = to; i >= from; i--) {
            if (!getLineText(document, i).trim().isEmpty()) return i;
        }
        return null;
    }

    private static void removeLine(@NotNull Document document, int line) {
        if (line < 0 || line >= document.getLineCount()) return;
        int start = document.getLineStartOffset(line);
        int end = document.getLineEndOffset(line);
        // include trailing newline if present
        if (end < document.getTextLength()) {
            CharSequence seq = document.getCharsSequence();
            if (seq.charAt(end) == '\n') {
                end += 1;
            }
        }
        document.deleteString(start, end);
    }

    private static int offsetAfterLine(@NotNull Document document, int line) {
        int end = document.getLineEndOffset(line);
        if (end < document.getTextLength()) {
            CharSequence seq = document.getCharsSequence();
            if (seq.charAt(end) == '\n') {
                end += 1;
            }
        }
        return end;
    }

    private static @NotNull String getLineText(@NotNull Document document, int line) {
        int start = document.getLineStartOffset(line);
        int end = document.getLineEndOffset(line);
        return document.getText().substring(start, end);
    }
}
