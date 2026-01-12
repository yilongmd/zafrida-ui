package com.zafrida.ui.fridaproject;

import org.jetbrains.annotations.NotNull;
import java.util.Objects;

public final class ZaFridaFridaProject {
    private final @NotNull String name;
    private final @NotNull ZaFridaPlatform platform;
    private final @NotNull String relativeDir; // android/<name> or ios/<name>

    public ZaFridaFridaProject(@NotNull String name, @NotNull ZaFridaPlatform platform, @NotNull String relativeDir) {
        this.name = name;
        this.platform = platform;
        this.relativeDir = relativeDir;
    }
    public @NotNull String getName() { return name; }
    public @NotNull ZaFridaPlatform getPlatform() { return platform; }
    public @NotNull String getRelativeDir() { return relativeDir; }

    @Override public String toString() { return name + " (" + relativeDir + ")"; }
    @Override public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ZaFridaFridaProject p)) return false;
        return name.equals(p.name) && platform == p.platform && relativeDir.equals(p.relativeDir);
    }
    @Override public int hashCode() { return Objects.hash(name, platform, relativeDir); }
}
