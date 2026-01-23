package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
/**
 * [数据模型] Frida 目标设备实体。
 * <p>
 * <strong>来源：</strong> 通常由解析 <code>frida-ls-devices</code> 命令的输出生成。
 * <p>
 * <strong>关键逻辑：</strong>
 * 在构建运行命令时：
 * <ul>
 * <li>如果 {@link #getMode()} 是 {@code DEVICE_ID} -> 使用 <code>-D device_id</code> (或 <code>-U</code>)。</li>
 * <li>如果 {@link #getMode()} 是 {@code HOST} -> 使用 <code>-H host:port</code>。</li>
 * </ul>
 */
public final class FridaDevice {

    /** 设备 ID 或序列号 */
    private final @NotNull String id;
    /** 设备类型（如 usb、remote） */
    private final @NotNull String type;
    /** 设备显示名称 */
    private final @NotNull String name;
    /** 设备寻址模式 */
    private final @NotNull FridaDeviceMode mode;
    /** 远程主机地址（HOST 模式可用） */
    private final @Nullable String host;

    /**
     * 构造函数。
     * @param id 设备 ID 或序列号
     * @param type 设备类型
     * @param name 设备名称
     * @param mode 寻址模式
     * @param host 远程主机地址（可为空）
     */
    public FridaDevice(@NotNull String id,
                       @NotNull String type,
                       @NotNull String name,
                       @NotNull FridaDeviceMode mode,
                       @Nullable String host) {
        this.id = id;
        this.type = type;
        this.name = name;
        this.mode = mode;
        this.host = host;
    }

    /**
     * 构造函数（默认 DEVICE_ID 模式）。
     * @param id 设备 ID 或序列号
     * @param type 设备类型
     * @param name 设备名称
     */
    public FridaDevice(@NotNull String id, @NotNull String type, @NotNull String name) {
        this(id, type, name, FridaDeviceMode.DEVICE_ID, null);
    }

    /**
     * 获取设备 ID。
     * @return 设备 ID
     */
    public @NotNull String getId() {
        return id;
    }

    /**
     * 获取设备类型。
     * @return 设备类型
     */
    public @NotNull String getType() {
        return type;
    }

    /**
     * 获取设备名称。
     * @return 设备名称
     */
    public @NotNull String getName() {
        return name;
    }

    /**
     * 获取寻址模式。
     * @return FridaDeviceMode
     */
    public @NotNull FridaDeviceMode getMode() {
        return mode;
    }

    /**
     * 获取远程主机地址。
     * @return 远程主机地址或 null
     */
    public @Nullable String getHost() {
        return host;
    }

    /**
     * 获取用于 UI 展示的设备文本。
     * @return 设备显示文本
     */
    public @NotNull String displayText() {
        if (mode == FridaDeviceMode.HOST) {
            return "[" + type + "] " + name + " (" + (host != null ? host : "?") + ")";
        }
        return "[" + type + "] " + name + " (" + id + ")";
    }

    /**
     * 返回显示文本。
     */
    @Override
    public String toString() {
        return displayText();
    }
}
