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

    /** 目标设备 */
    private final @NotNull FridaDevice device;
    /** 运行模式 */
    private final @NotNull FridaRunMode mode;
    /** 脚本文件路径 */
    private final @NotNull String scriptPath;
    /** 额外命令参数 */
    private final @NotNull String extraArgs;

    /**
     * 构造函数。
     * @param device 目标设备
     * @param mode 运行模式
     * @param scriptPath 脚本文件路径
     * @param extraArgs 额外命令参数
     */
    public FridaRunConfig(@NotNull FridaDevice device,
                          @NotNull FridaRunMode mode,
                          @NotNull String scriptPath,
                          @NotNull String extraArgs) {
        this.device = device;
        this.mode = mode;
        this.scriptPath = scriptPath;
        this.extraArgs = extraArgs;
    }

    /**
     * 获取目标设备。
     * @return FridaDevice
     */
    public @NotNull FridaDevice getDevice() {
        return device;
    }

    /**
     * 获取运行模式。
     * @return FridaRunMode
     */
    public @NotNull FridaRunMode getMode() {
        return mode;
    }

    /**
     * 获取脚本路径。
     * @return 脚本路径
     */
    public @NotNull String getScriptPath() {
        return scriptPath;
    }

    /**
     * 获取额外参数。
     * @return 额外参数字符串
     */
    public @NotNull String getExtraArgs() {
        return extraArgs;
    }
}
