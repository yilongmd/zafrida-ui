package com.zafrida.ui.fridaproject;

import org.jetbrains.annotations.NotNull;

public final class ZaFridaProjectFiles {
    private ZaFridaProjectFiles() {
    }

    public static final String WORKSPACE_FILE = "zafrida-workspace.xml";
    public static final String PROJECT_FILE = "zafrida-project.xml";

    // 旧项目仍可能依赖 agent.js，不能直接移除该回退名。
    public static final String DEFAULT_MAIN_SCRIPT = "agent.js";

    public static @NotNull String defaultMainScriptName(@NotNull String projectName) {
        String trimmed = projectName.trim();
        if (trimmed.isEmpty()) {
            return DEFAULT_MAIN_SCRIPT;
        }
        String lower = trimmed.toLowerCase(java.util.Locale.ROOT);
        if (lower.endsWith(".js") || lower.endsWith(".ts")) {
            return trimmed;
        }
        return String.format("%s.js", trimmed);
    }
}
