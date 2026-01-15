package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;
/**
 * [运行模式]以此应用包名/BundleID 启动新进程 (Spawn)。
 * <p>
 * <strong>映射关系：</strong>
 * 对应 frida 命令行参数 <code>-f &lt;identifier&gt;</code>。
 * <p>
 * <strong>逆向场景：</strong>
 * "冷启动"模式。用于在应用启动的最早期进行 Hook（例如 Hook {@code Application.attachBaseContext}
 * 或 {@code main} 函数），或者当应用无法中途附加时使用。
 */
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
        return "Spawn(-f " + identifier + ")";
    }
}
