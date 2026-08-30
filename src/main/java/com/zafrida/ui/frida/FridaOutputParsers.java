package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class FridaOutputParsers {

    private FridaOutputParsers() {
    }

    public static @NotNull List<FridaDevice> parseDevices(@NotNull String stdout) {
        String clean = stripAnsi(stdout);
        if (clean.trim().isEmpty()) {
            return Collections.emptyList();
        }

        List<String> lines = nonEmptyLines(clean);
        if (lines.isEmpty()) {
            return Collections.emptyList();
        }

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

                if (id.isEmpty() || type.isEmpty()) {
                    continue;
                }
                if (id.equalsIgnoreCase("Id") && type.equalsIgnoreCase("Type")) {
                    continue;
                }
                if (isDashOnlyToken(id) || isDashOnlyToken(type)) {
                    continue;
                }

                out.add(new FridaDevice(id, type, name));
            }
        }
        return out;
    }

    public static @NotNull List<FridaProcess> parseProcesses(@NotNull String stdout) {
        String clean = stripAnsi(stdout);
        if (clean.trim().isEmpty()) {
            return Collections.emptyList();
        }

        List<String> lines = nonEmptyLines(clean);
        if (lines.isEmpty()) {
            return Collections.emptyList();
        }

        int headerIndex = indexOfHeader(lines, "PID");
        if (headerIndex >= 0) {
            return parseProcessTable(lines, headerIndex);
        }

        List<FridaProcess> out = new ArrayList<>();
        for (String line : lines) {
            String[] parts = splitBy2PlusSpaces(line, 3);
            if (parts.length >= 2) {
                String pidStr = parts[0].trim();
                if (pidStr.equalsIgnoreCase("PID") || isDashOnlyToken(pidStr)) {
                    continue;
                }

                Integer pid = tryParseInt(pidStr);
                String name = parts[1].trim();
                String identifier = null;
                if (parts.length >= 3) {
                    identifier = emptyToNull(parts[2].trim());
                }

                if (name.equalsIgnoreCase("Name") && pid == null) {
                    continue;
                }

                out.add(new FridaProcess(pid, name, identifier));
            }
        }
        return out;
    }

    private static @NotNull List<FridaProcess> parseProcessTable(@NotNull List<String> lines, int headerIndex) {
        String header = lines.get(headerIndex);
        int nameColumn = header.indexOf("Name");
        int identifierColumn = header.indexOf("Identifier");
        if (nameColumn < 0) {
            return Collections.emptyList();
        }

        List<String> dataLines = dropSeparators(lines.subList(headerIndex + 1, lines.size()));
        List<FridaProcess> processes = new ArrayList<>();
        for (String line : dataLines) {
            if (line.length() <= nameColumn) {
                continue;
            }
            String pidText = line.substring(0, nameColumn).trim();
            if (pidText.isEmpty() || isDashOnlyToken(pidText)) {
                pidText = "-";
            }

            String name;
            String identifier = null;
            if (identifierColumn > nameColumn && line.length() > identifierColumn) {
                name = line.substring(nameColumn, identifierColumn).trim();
                identifier = emptyToNull(line.substring(identifierColumn).trim());
            } else {
                name = line.substring(nameColumn).trim();
            }
            if (name.isEmpty()) {
                continue;
            }
            processes.add(new FridaProcess(tryParseInt(pidText), name, identifier));
        }
        return processes;
    }

    private static @NotNull List<String> nonEmptyLines(@NotNull String text) {
        String[] raw = text.split("\\R");
        List<String> lines = new ArrayList<>();
        for (String s : raw) {
            String t = s.trim();
            if (!t.isEmpty()) {
                lines.add(s.stripTrailing());
            }
        }
        return lines;
    }

    private static int indexOfHeader(@NotNull List<String> lines, @NotNull String headerStartsWith) {
        for (int i = 0; i < lines.size(); i++) {
            String t = lines.get(i).trim();
            if (t.regionMatches(true, 0, headerStartsWith, 0, headerStartsWith.length())) {
                return i;
            }
        }
        return -1;
    }

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

    private static boolean isSeparatorLine(@NotNull String t) {
        // 兼容 ASCII、Unicode 横线及带表格边框的分隔行。
        boolean hasDash = false;
        for (int i = 0; i < t.length(); i++) {
            char ch = t.charAt(i);

            if (ch == '-' || ch == '─' || ch == '━' || ch == '—') {
                hasDash = true;
                continue;
            }

            if (Character.isWhitespace(ch) || ch == '|' || ch == '+' ) {
                continue;
            }

            return false;
        }
        return hasDash;
    }

    private static boolean isDashOnlyToken(@NotNull String token) {
        String t = token.trim();
        if (t.isEmpty()) {
            return true;
        }

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


    private static @NotNull String[] splitBy2PlusSpaces(@NotNull String line, int limit) {
        String normalized = line.trim().replaceAll(" {2,}", "\t");
        if (limit <= 0) {
            return normalized.split("\t");
        }
        return normalized.split("\t", limit);
    }

    private static Integer tryParseInt(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static String emptyToNull(String s) {
        if (s == null || s.isEmpty()) {
            return null;
        }
        return s;
    }

    private static @NotNull String stripAnsi(@NotNull String text) {
        StringBuilder sb = new StringBuilder(text.length());
        final char ESC = 27;
        int i = 0;
        while (i < text.length()) {
            char c = text.charAt(i);
            if (c == ESC) {
                // 跳过 ANSI CSI 转义序列。
                int j = i + 1;
                if (j < text.length() && text.charAt(j) == '[') {
                    j++;
                    while (j < text.length()) {
                        char cj = text.charAt(j);
                        if ((cj >= '0' && cj <= '9') || cj == ';') {
                            j++;
                            continue;
                        }
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
