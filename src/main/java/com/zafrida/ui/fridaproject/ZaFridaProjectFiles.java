package com.zafrida.ui.fridaproject;

public final class ZaFridaProjectFiles {
    private ZaFridaProjectFiles() {}
    // IDE 项目根目录：记录有哪些 ZAFrida 项目 + 上次选中
    public static final String WORKSPACE_FILE = "zafrida-workspace.xml";
    // 每个 Frida 项目文件夹内：记录该项目配置/状态
    public static final String PROJECT_FILE = "zafrida-project.xml";

    public static final String DEFAULT_MAIN_SCRIPT = "agent.js";
}
