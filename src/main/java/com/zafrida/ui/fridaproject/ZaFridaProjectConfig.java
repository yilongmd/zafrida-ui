package com.zafrida.ui.fridaproject;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public final class ZaFridaProjectConfig {
    public static final int VERSION = 1;

    public @NotNull String name = "";
    public @NotNull ZaFridaPlatform platform = ZaFridaPlatform.ANDROID;

    // 主脚本（相对项目文件夹）
    public @NotNull String mainScript = ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT;

    // 上次调试目标（Android package / iOS bundle）
    public @Nullable String lastTarget = null;
}
