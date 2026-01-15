package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;
/**
 * [运行模式] 按名称附加 (Attach by Name)。
 * <p>
 * <strong>映射关系：</strong>
 * 对应 frida 命令行参数 <code>-n &lt;name&gt;</code>。
 * <p>
 * <strong>场景：</strong>
 * 当用户提供的是进程名（如 "com.android.phone" 或 "WhatsApp"）而非 PID，且目标应用已经在运行时使用。
 */
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
        return "Attach(-n " + name + ")";
    }
}
