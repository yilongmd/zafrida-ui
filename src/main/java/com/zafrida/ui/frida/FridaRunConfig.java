package com.zafrida.ui.frida;

import com.zafrida.ui.ui.ZaFridaRunPanel;
import org.jetbrains.annotations.NotNull;

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
