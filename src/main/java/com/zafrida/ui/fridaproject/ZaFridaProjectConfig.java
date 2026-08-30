package com.zafrida.ui.fridaproject;

import com.zafrida.ui.frida.FridaConnectionMode;
import com.zafrida.ui.frida.FridaProcessScope;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public final class ZaFridaProjectConfig {
    public static final int VERSION = 2;

    public @NotNull String name = "";
    public @NotNull ZaFridaPlatform platform = ZaFridaPlatform.ANDROID;
    public @NotNull String mainScript = ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT;
    public @NotNull String attachScript = "";
    public boolean spawnMode = true;
    public @NotNull String extraArgs = "";
    public @Nullable String lastTarget = null;
    public @NotNull FridaConnectionMode connectionMode = FridaConnectionMode.USB;
    public @NotNull String remoteHost = "127.0.0.1";
    public int remotePort = 14725;
    public @Nullable String lastDeviceId = null;
    public @Nullable String lastDeviceHost = null;
    public boolean targetManual = true;
    public @NotNull FridaProcessScope processScope = FridaProcessScope.RUNNING_APPS;

    /** 留空时使用当前 IDE 项目解释器；也可填写本地解释器文件或 venv/conda 等环境根目录。 */
    public @NotNull String pythonEnvironmentPath = "";
}
