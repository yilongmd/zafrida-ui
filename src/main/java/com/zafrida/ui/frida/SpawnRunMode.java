package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;

public final class SpawnRunMode implements FridaRunMode {

    private final @NotNull String identifier;

    public SpawnRunMode(@NotNull String identifier) {
        this.identifier = identifier;
    }

    public @NotNull String getIdentifier() {
        return identifier;
    }

    @Override
    public String toString() {
        return String.format("Spawn(-f %s)", identifier);
    }
}
