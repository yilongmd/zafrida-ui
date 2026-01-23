package com.zafrida.ui.fridaproject;

import org.jetbrains.annotations.NotNull;
/**
 * [常量定义] ZAFrida 项目文件结构协议。
 * <p>
 * <strong>架构规范：</strong>
 * <ul>
 * <li>{@link #WORKSPACE_FILE}: 位于 IDE 项目根目录 (.idea 同级)，是全局注册表，记录当前 IDE 项目下有哪些 ZAFrida 子项目。</li>
 * <li>{@link #PROJECT_FILE}: 位于每个子项目文件夹内，存储该 App 特有的 Hook 配置（包名、脚本路径等）。</li>
 * <li>{@link #DEFAULT_MAIN_SCRIPT}: 兼容旧项目的默认入口脚本名称。</li>
 * </ul>
 */
public final class ZaFridaProjectFiles {
    /**
     * 私有构造函数，禁止实例化。
     */
    private ZaFridaProjectFiles() {
    }

    /** IDE 项目根目录：记录有哪些 ZAFrida 项目 + 上次选中 */
    public static final String WORKSPACE_FILE = "zafrida-workspace.xml";
    /** 每个 Frida 项目文件夹内：记录该项目配置/状态 */
    public static final String PROJECT_FILE = "zafrida-project.xml";

    // Legacy fallback when project-specific default is unavailable.
    // 当项目缺省入口脚本不可用时的兼容回退名称。
    /** 旧版本默认入口脚本名称 */
    public static final String DEFAULT_MAIN_SCRIPT = "agent.js";

    /**
     * 生成默认主脚本文件名。
     * @param projectName 项目名称
     * @return 脚本文件名
     */
    public static @NotNull String defaultMainScriptName(@NotNull String projectName) {
        String trimmed = projectName.trim();
        if (trimmed.isEmpty()) return DEFAULT_MAIN_SCRIPT;
        String lower = trimmed.toLowerCase(java.util.Locale.ROOT);
        return lower.endsWith(".js") ? trimmed : trimmed + ".js";
    }
}
