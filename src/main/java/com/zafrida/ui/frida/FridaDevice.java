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

    private final @NotNull String id;
    private final @NotNull String type;
    private final @NotNull String name;
    private final @NotNull FridaDeviceMode mode;
    private final @Nullable String host;

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

    public FridaDevice(@NotNull String id, @NotNull String type, @NotNull String name) {
        this(id, type, name, FridaDeviceMode.DEVICE_ID, null);
    }

    public @NotNull String getId() {
        return id;
    }

    public @NotNull String getType() {
        return type;
    }

    public @NotNull String getName() {
        return name;
    }

    public @NotNull FridaDeviceMode getMode() {
        return mode;
    }

    public @Nullable String getHost() {
        return host;
    }

    public @NotNull String displayText() {
        if (mode == FridaDeviceMode.HOST) {
            return "[" + type + "] " + name + " (" + (host != null ? host : "?") + ")";
        }
        return "[" + type + "] " + name + " (" + id + ")";
    }

    @Override
    public String toString() {
        return displayText();
    }
}
