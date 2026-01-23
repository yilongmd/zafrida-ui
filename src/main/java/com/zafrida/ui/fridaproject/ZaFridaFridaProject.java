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
    /** 项目名称 */
    private final @NotNull String name;
    /** 目标平台 */
    private final @NotNull ZaFridaPlatform platform;
    /** 相对目录路径 */
    private final @NotNull String relativeDir; // android/<name> or ios/<name>
    // android/<name> 或 ios/<name>

    /**
     * 构造函数。
     * @param name 项目名称
     * @param platform 目标平台
     * @param relativeDir 相对目录路径
     */
    public ZaFridaFridaProject(@NotNull String name, @NotNull ZaFridaPlatform platform, @NotNull String relativeDir) {
        this.name = name;
        this.platform = platform;
        this.relativeDir = relativeDir;
    }

    /**
     * 获取项目名称。
     * @return 项目名称
     */
    public @NotNull String getName() {
        return name;
    }

    /**
     * 获取目标平台。
     * @return ZaFridaPlatform
     */
    public @NotNull ZaFridaPlatform getPlatform() {
        return platform;
    }

    /**
     * 获取相对目录路径。
     * @return 相对目录路径
     */
    public @NotNull String getRelativeDir() {
        return relativeDir;
    }

    /**
     * 返回项目简要描述。
     */
    @Override
    public String toString() {
        return name + " (" + relativeDir + ")";
    }

    /**
     * 判断项目是否相等。
     * @param o 比较对象
     * @return true 表示相等
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ZaFridaFridaProject p)) return false;
        return name.equals(p.name) && platform == p.platform && relativeDir.equals(p.relativeDir);
    }

    /**
     * 计算哈希值。
     * @return 哈希值
     */
    @Override
    public int hashCode() {
        return Objects.hash(name, platform, relativeDir);
    }
}
