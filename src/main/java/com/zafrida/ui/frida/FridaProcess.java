package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public final class FridaProcess {

    private final @Nullable Integer pid;
    private final @NotNull String name;
    private final @Nullable String identifier;

    public FridaProcess(@Nullable Integer pid, @NotNull String name, @Nullable String identifier) {
        this.pid = pid;
        this.name = name;
        this.identifier = identifier;
    }

    public @Nullable Integer getPid() {
        return pid;
    }

    public @NotNull String getName() {
        return name;
    }

    public @Nullable String getIdentifier() {
        return identifier;
    }
}
