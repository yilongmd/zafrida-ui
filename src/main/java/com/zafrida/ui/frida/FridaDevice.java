package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

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
