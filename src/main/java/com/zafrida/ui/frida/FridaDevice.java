package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;

public final class FridaDevice {

    public static final String TYPE_USB = "usb";
    /** 旧版本用它泛指「任意 USB 设备」，对应 CLI 的 {@code -U}；它不是 adb serial。 */
    public static final String GENERIC_USB_ID = "usb";
    private static final String TYPE_NOT_CONNECTED = "offline";
    private static final String NAME_NOT_CONNECTED = "Not connected";

    private final @NotNull String id;
    private final @NotNull String type;
    private final @NotNull String name;
    private final @NotNull FridaDeviceMode mode;
    private final @Nullable String host;
    private final boolean connected;

    public FridaDevice(@NotNull String id,
                       @NotNull String type,
                       @NotNull String name,
                       @NotNull FridaDeviceMode mode,
                       @Nullable String host) {
        this(id, type, name, mode, host, true);
    }

    public FridaDevice(@NotNull String id, @NotNull String type, @NotNull String name) {
        this(id, type, name, FridaDeviceMode.DEVICE_ID, null, true);
    }

    private FridaDevice(@NotNull String id,
                        @NotNull String type,
                        @NotNull String name,
                        @NotNull FridaDeviceMode mode,
                        @Nullable String host,
                        boolean connected) {
        this.id = id;
        this.type = type;
        this.name = name;
        this.mode = mode;
        this.host = host;
        this.connected = connected;
    }

    /**
     * 已保存但当前枚举不到的设备占位，只用于在界面上保留用户的选择；
     * 不得传给 Frida CLI 或 adb，调用方必须先检查 {@link #isConnected()}。
     */
    public static @NotNull FridaDevice notConnected(@NotNull String id) {
        return new FridaDevice(id, TYPE_NOT_CONNECTED, NAME_NOT_CONNECTED, FridaDeviceMode.DEVICE_ID, null, false);
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

    public boolean isConnected() {
        return connected;
    }

    public boolean isUsb() {
        return TYPE_USB.equalsIgnoreCase(type);
    }

    /** Frida CLI 的设备定位参数：{@code -H host:port}、{@code -U} 或 {@code -D id}。 */
    public @NotNull List<String> cliArgs() {
        if (!connected) {
            throw new IllegalArgumentException(String.format("Device is not connected: %s", id));
        }
        List<String> args = new ArrayList<>();
        if (mode == FridaDeviceMode.HOST) {
            if (host == null || host.trim().isEmpty()) {
                throw new IllegalArgumentException("Device host is null/blank");
            }
            args.add("-H");
            args.add(host);
            return args;
        }
        if (GENERIC_USB_ID.equalsIgnoreCase(id)) {
            args.add("-U");
            return args;
        }
        args.add("-D");
        args.add(id);
        return args;
    }

    public @NotNull String displayText() {
        if (!connected) {
            return String.format("%s (not connected)", id);
        }
        if (mode == FridaDeviceMode.HOST) {
            String displayHost = host;
            if (displayHost == null) {
                displayHost = "?";
            }
            return String.format("[%s] %s (%s)", type, name, displayHost);
        }
        return String.format("[%s] %s (%s)", type, name, id);
    }

    @Override
    public String toString() {
        return displayText();
    }
}
