package com.zafrida.ui.frida;

import com.zafrida.ui.ui.ZaFridaRunPanel;
import org.jetbrains.annotations.NotNull;

/**
 * [DTO] Frida 运行参数聚合对象。
 * <p>
 * 包含运行所需的所有不可变信息：目标设备、运行模式（Spawn/Attach）、脚本路径及额外参数。
 * 在 {@link ZaFridaRunPanel} 中构建，传递给 {@link FridaCliService} 使用。
 */
public final class FridaRunConfig {

    private final @NotNull FridaDevice device;
    private final @NotNull FridaRunMode mode;
    private final @NotNull String scriptPath;
    private final @NotNull String extraArgs;

    public FridaRunConfig(@NotNull FridaDevice device,
                          @NotNull FridaRunMode mode,
                          @NotNull String scriptPath,
                          @NotNull String extraArgs) {
        this.device = device;
        this.mode = mode;
        this.scriptPath = scriptPath;
        this.extraArgs = extraArgs;
    }

    public @NotNull FridaDevice getDevice() {
        return device;
    }

    public @NotNull FridaRunMode getMode() {
        return mode;
    }

    public @NotNull String getScriptPath() {
        return scriptPath;
    }

    public @NotNull String getExtraArgs() {
        return extraArgs;
    }
}
