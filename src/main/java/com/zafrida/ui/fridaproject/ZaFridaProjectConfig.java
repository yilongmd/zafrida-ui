package com.zafrida.ui.fridaproject;

import com.zafrida.ui.frida.FridaConnectionMode;
import com.zafrida.ui.frida.FridaProcessScope;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
/**
 * [DTO] 单个 ZAFrida 子项目的配置模型。
 * <p>
 * <strong>数据流：</strong>
 * 映射到 {@code zafrida-project.xml} 文件。
 * 存储特定 App 的逆向工程上下文：
 * <ul>
 * <li>{@code mainScript}: 入口脚本路径（相对路径）。</li>
 * <li>{@code attachScript}: 附加脚本路径（相对路径）。</li>
 * <li>{@code connectionMode}: 连接方式 (USB/Remote)。</li>
 * <li>{@code lastTarget}: 上次调试的包名或 PID。</li>
 * </ul>
 */
public final class ZaFridaProjectConfig {
    public static final int VERSION = 1;

    public @NotNull String name = "";
    public @NotNull ZaFridaPlatform platform = ZaFridaPlatform.ANDROID;

    // 主脚本（相对项目文件夹）
    public @NotNull String mainScript = ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT;

    // 附加脚本（相对项目文件夹）
    public @NotNull String attachScript = "";

    // Run 模式：true=Spawn, false=Attach
    public boolean spawnMode = true;

    // 额外参数（传给 frida CLI）
    public @NotNull String extraArgs = "";

    // 上次调试目标（Android package / iOS bundle）
    public @Nullable String lastTarget = null;

    public @NotNull FridaConnectionMode connectionMode = FridaConnectionMode.USB;
    public @NotNull String remoteHost = "127.0.0.1";
    public int remotePort = 14725;

    public @Nullable String lastDeviceId = null;
    public @Nullable String lastDeviceHost = null;

    public boolean targetManual = true;

    public @NotNull FridaProcessScope processScope = FridaProcessScope.RUNNING_APPS;
}
