package com.zafrida.ui.fridaproject;

import org.jetbrains.annotations.NotNull;
import java.util.Objects;
/**
 * [实体类] 运行时 ZAFrida 项目对象。
 * <p>
 * <strong>架构角色：</strong>
 * 代表一个已加载的 Frida 子项目。
 * <p>
 * <strong>关键属性：</strong>
 * <ul>
 * <li>{@code relativeDir}: 项目根目录相对于 IDE 项目根目录的路径（例如 {@code android/MyApp}）。</li>
 * <li>{@code platform}: 目标平台 (Android/iOS)，决定了默认的脚本模板和目录结构。</li>
 * </ul>
 */
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
