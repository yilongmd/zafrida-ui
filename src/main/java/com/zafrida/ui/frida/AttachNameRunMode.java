package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;

public final class AttachNameRunMode implements FridaRunMode {

    private final @NotNull String name;

    public AttachNameRunMode(@NotNull String name) {
        this.name = name;
    }

    public @NotNull String getName() {
        return name;
    }

    @Override
    public String toString() {
        return String.format("Attach(-N %s)", name);
    }
}
