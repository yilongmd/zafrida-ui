package com.zafrida.ui.util;

import org.jetbrains.annotations.NotNull;

import java.util.regex.Pattern;

/** 只转换新插入的片段和模板，不扫描或重写用户已有脚本。 */
public final class FridaJsCompatibilityUtil {

    private static final Pattern FIND_EXPORT_WITH_NULL_MODULE = Pattern.compile(
            "Module\\s*\\.\\s*findExportByName\\s*\\(\\s*null\\s*,\\s*([\"'][^\"'\\r\\n]+[\"'])\\s*\\)"
    );

    private static final Pattern FIND_EXPORT_WITH_MODULE_NAME = Pattern.compile(
            "Module\\s*\\.\\s*findExportByName\\s*\\(\\s*([\"'][^\"'\\r\\n]+[\"'])\\s*,\\s*([\"'][^\"'\\r\\n]+[\"'])\\s*\\)"
    );

    private FridaJsCompatibilityUtil() {
    }

    public static @NotNull String adaptForFridaVersion(@NotNull String jsCode, boolean frida17OrLater) {
        if (!frida17OrLater) {
            return jsCode;
        }
        return adaptForFrida17(jsCode);
    }

    public static @NotNull String adaptForFrida17(@NotNull String jsCode) {
        String adapted = FIND_EXPORT_WITH_NULL_MODULE
                .matcher(jsCode)
                .replaceAll("Module.getGlobalExportByName($1)");
        adapted = FIND_EXPORT_WITH_MODULE_NAME
                .matcher(adapted)
                .replaceAll("Process.getModuleByName($1).getExportByName($2)");
        return adapted;
    }
}
