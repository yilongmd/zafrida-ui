package com.zafrida.ui.util;

import org.jetbrains.annotations.NotNull;

public final class ZaFridaTextUtil {

    private ZaFridaTextUtil() {
    }

    public static boolean isNumeric(@NotNull String value) {
        for (int i = 0; i < value.length(); i++) {
            if (!Character.isDigit(value.charAt(i))) {
                return false;
            }
        }
        return !value.isEmpty();
    }
}
