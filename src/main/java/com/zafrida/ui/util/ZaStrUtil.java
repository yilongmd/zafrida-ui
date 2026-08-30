package com.zafrida.ui.util;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public final class ZaStrUtil {

    private ZaStrUtil() {
    }

    public static boolean isBlank(@Nullable CharSequence value) {
        if (value == null || value.length() == 0) {
            return true;
        }
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (!Character.isWhitespace(current)
                    && !Character.isSpaceChar(current)
                    && current != '\uFEFF') {
                return false;
            }
        }
        return true;
    }

    public static boolean isNotBlank(@Nullable CharSequence value) {
        return !isBlank(value);
    }

    public static @NotNull String nullToEmpty(@Nullable CharSequence value) {
        if (value == null) {
            return "";
        }
        return value.toString();
    }

    public static @Nullable String trim(@Nullable CharSequence value) {
        if (value == null) {
            return null;
        }
        int start = 0;
        int end = value.length();
        while (start < end && isBlankCharacter(value.charAt(start))) {
            start++;
        }
        while (start < end && isBlankCharacter(value.charAt(end - 1))) {
            end--;
        }
        return value.subSequence(start, end).toString();
    }

    public static int compareVersion(@Nullable CharSequence first, @Nullable CharSequence second) {
        String firstText = toNullableString(first);
        String secondText = toNullableString(second);
        if (firstText == null && secondText == null) {
            return 0;
        }
        if (firstText == null) {
            return -1;
        }
        if (secondText == null) {
            return 1;
        }

        String[] firstParts = firstText.split("[.-]");
        String[] secondParts = secondText.split("[.-]");
        int partCount = Math.max(firstParts.length, secondParts.length);
        for (int index = 0; index < partCount; index++) {
            String firstPart = "0";
            if (index < firstParts.length) {
                firstPart = firstParts[index];
            }
            String secondPart = "0";
            if (index < secondParts.length) {
                secondPart = secondParts[index];
            }
            int comparison = compareVersionPart(firstPart, secondPart);
            if (comparison != 0) {
                return comparison;
            }
        }
        return 0;
    }

    private static boolean isBlankCharacter(char value) {
        return Character.isWhitespace(value) || Character.isSpaceChar(value) || value == '\uFEFF';
    }

    private static @Nullable String toNullableString(@Nullable CharSequence value) {
        if (value == null) {
            return null;
        }
        return value.toString();
    }

    private static int compareVersionPart(@NotNull String first, @NotNull String second) {
        boolean firstNumeric = isNumeric(first);
        boolean secondNumeric = isNumeric(second);
        if (firstNumeric && secondNumeric) {
            if (first.length() != second.length()) {
                if (first.length() > second.length()) {
                    return 1;
                }
                return -1;
            }
            return first.compareTo(second);
        }
        return first.compareToIgnoreCase(second);
    }

    private static boolean isNumeric(@NotNull String value) {
        if (value.isEmpty()) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            if (!Character.isDigit(value.charAt(index))) {
                return false;
            }
        }
        return true;
    }
}
