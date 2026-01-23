package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * [工具类] Frida CLI 输出解析器。
 * <p>
 * 负责解析 `frida-ps` 和 `frida-ls-devices` 的标准输出（Stdout），
 * 包含去除 ANSI 颜色代码、表头识别和列数据提取逻辑。
 */
public final class FridaOutputParsers {

    /**
     * 私有构造函数，禁止实例化。
     */
    private FridaOutputParsers() {
    }

    /**
     * Parses output of `frida-ls-devices`.
     * Expected columns: Id  Type  Name
     * 解析 `frida-ls-devices` 输出。
     * 期望列：Id、Type、Name。
     */
    public static @NotNull List<FridaDevice> parseDevices(@NotNull String stdout) {
        String clean = stripAnsi(stdout).trim();
        if (clean.isEmpty()) return Collections.emptyList();

        List<String> lines = nonEmptyLines(clean);
        if (lines.isEmpty()) return Collections.emptyList();

        int headerIndex = indexOfHeader(lines, "Id");
        List<String> dataLines = headerIndex >= 0
                ? dropSeparators(lines.subList(headerIndex + 1, lines.size()))
                : lines;

        List<FridaDevice> out = new ArrayList<>();
        for (String line : dataLines) {
            String[] parts = splitBy2PlusSpaces(line, 3);
            if (parts.length >= 3) {
                String id = parts[0].trim();
                String type = parts[1].trim();
                String name = parts[2].trim();

                // skip header/separator junk
                // 跳过表头/分隔行等无效内容
                if (id.isEmpty() || type.isEmpty()) continue;
                if (id.equalsIgnoreCase("Id") && type.equalsIgnoreCase("Type")) continue;
                if (isDashOnlyToken(id) || isDashOnlyToken(type)) continue;

                out.add(new FridaDevice(id, type, name));
            }
        }
        return out;
    }

    /**
     * Parses output of `frida-ps`.
     * Expected columns: PID  Name  Identifier
     * 解析 `frida-ps` 输出。
     * 期望列：PID、Name、Identifier。
     */
    public static @NotNull List<FridaProcess> parseProcesses(@NotNull String stdout) {
        String clean = stripAnsi(stdout).trim();
        if (clean.isEmpty()) return Collections.emptyList();

        List<String> lines = nonEmptyLines(clean);
        if (lines.isEmpty()) return Collections.emptyList();

        int headerIndex = indexOfHeader(lines, "PID");
        List<String> dataLines = headerIndex >= 0
                ? dropSeparators(lines.subList(headerIndex + 1, lines.size()))
                : lines;

        List<FridaProcess> out = new ArrayList<>();
        for (String line : dataLines) {
            String[] parts = splitBy2PlusSpaces(line, 3);
            if (parts.length >= 2) {
                String pidStr = parts[0].trim();
                if (pidStr.equalsIgnoreCase("PID") || isDashOnlyToken(pidStr)) continue;

                Integer pid = tryParseInt(pidStr);
                String name = parts[1].trim();
                String identifier = parts.length >= 3 ? emptyToNull(parts[2].trim()) : null;

                // name 也可能是 "Name" 之类的表头残留，顺手过滤
                if (name.equalsIgnoreCase("Name") && pid == null) continue;

                out.add(new FridaProcess(pid, name, identifier));
            }
        }
        return out;
    }

    /**
     * 过滤并返回非空行列表。
     * @param text 原始文本
     * @return 非空行列表
     */
    private static @NotNull List<String> nonEmptyLines(@NotNull String text) {
        String[] raw = text.split("\\R");
        List<String> lines = new ArrayList<>();
        for (String s : raw) {
            String t = s.trim();
            if (!t.isEmpty()) lines.add(s.trim());
        }
        return lines;
    }

    /**
     * 查找表头所在行的索引。
     * @param lines 文本行列表
     * @param headerStartsWith 表头起始关键字
     * @return 表头索引，未找到返回 -1
     */
    private static int indexOfHeader(@NotNull List<String> lines, @NotNull String headerStartsWith) {
        for (int i = 0; i < lines.size(); i++) {
            String t = lines.get(i).trim();
            if (t.regionMatches(true, 0, headerStartsWith, 0, headerStartsWith.length())) {
                return i;
            }
        }
        return -1;
    }

    /**
     * 从列表前部移除空行/分隔线。
     * @param lines 原始行列表
     * @return 去掉分隔线后的子列表
     */
    private static @NotNull List<String> dropSeparators(@NotNull List<String> lines) {
        int idx = 0;
        while (idx < lines.size()) {
            String t = lines.get(idx).trim();
            if (t.isEmpty()) {
                idx++;
                continue;
            }
            if (isSeparatorLine(t)) {
                idx++;
                continue;
            }
            break;
        }
        return lines.subList(idx, lines.size());
    }

    /**
     * 判断是否为分隔线行。
     * @param t 待判断的行文本
     * @return true 表示分隔线
     */
    private static boolean isSeparatorLine(@NotNull String t) {
        // Accept things like:
        // 接受如下分隔线形式：
        // "---- ---- ----"
        // 例如："---- ---- ----"
        // "──────────────"
        // 例如："──────────────"
        // "| ---- | ---- |"
        // 例如："| ---- | ---- |"
        boolean hasDash = false;
        for (int i = 0; i < t.length(); i++) {
            char ch = t.charAt(i);

            // common dash-like chars
            // 常见的“横线”字符
            if (ch == '-' || ch == '─' || ch == '━' || ch == '—') {
                hasDash = true;
                continue;
            }

            // allow whitespace and some table border chars
            // 允许空白与表格边框字符
            if (Character.isWhitespace(ch) || ch == '|' || ch == '+' ) {
                continue;
            }

            // any other char => not a separator line
            // 其他字符出现则判定为非分隔线
            return false;
        }
        return hasDash;
    }

    /**
     * 判断 token 是否仅由“横线”组成。
     * @param token 待判断文本
     * @return true 表示仅包含横线
     */
    private static boolean isDashOnlyToken(@NotNull String token) {
        String t = token.trim();
        if (t.isEmpty()) return true;

        boolean hasDash = false;
        for (int i = 0; i < t.length(); i++) {
            char ch = t.charAt(i);
            if (ch == '-' || ch == '─' || ch == '━' || ch == '—') {
                hasDash = true;
                continue;
            }
            return false;
        }
        return hasDash;
    }


    /**
     * 以 2 个及以上空格为分隔符拆分行文本。
     * @param line 输入行
     * @param limit 最大拆分数，<=0 表示不限制
     * @return 拆分后的字段数组
     */
    private static @NotNull String[] splitBy2PlusSpaces(@NotNull String line, int limit) {
        // Replace 2+ spaces with a single delimiter, then split.
        // 将 2 个及以上空格替换为分隔符后再拆分。
        String normalized = line.trim().replaceAll(" {2,}", "\t");
        if (limit <= 0) return normalized.split("\t");
        return normalized.split("\t", limit);
    }

    /**
     * 尝试将字符串解析为整数。
     * @param s 输入字符串
     * @return 解析结果或 null
     */
    private static Integer tryParseInt(String s) {
        try {
            return Integer.parseInt(s);
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * 空字符串转为 null。
     * @param s 输入字符串
     * @return 非空字符串或 null
     */
    private static String emptyToNull(String s) {
        return s == null || s.isEmpty() ? null : s;
    }

    /**
     * Minimal ANSI escape removal (enough for most frida tools outputs).
     * 最小化 ANSI 转义序列清理（适用于大多数 frida 工具输出）。
     */
    private static @NotNull String stripAnsi(@NotNull String text) {
        StringBuilder sb = new StringBuilder(text.length());
        final char ESC = 27;
        int i = 0;
        while (i < text.length()) {
            char c = text.charAt(i);
            if (c == ESC) {
                // Skip sequences like ESC [ ... m
                // 跳过类似 ESC [ ... m 的转义序列
                int j = i + 1;
                if (j < text.length() && text.charAt(j) == '[') {
                    j++;
                    while (j < text.length()) {
                        char cj = text.charAt(j);
                        if ((cj >= '0' && cj <= '9') || cj == ';') {
                            j++;
                            continue;
                        }
                        // Typically ends with 'm'
                        // 通常以 'm' 结束
                        j++;
                        break;
                    }
                    i = j;
                    continue;
                }
            }
            sb.append(c);
            i++;
        }
        return sb.toString();
    }
}
