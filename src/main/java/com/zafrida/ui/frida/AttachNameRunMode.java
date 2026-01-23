package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;
/**
 * [运行模式] 按名称附加 (Attach by Name)。
 * <p>
 * <strong>映射关系：</strong>
 * 对应 frida 命令行参数 <code>-N &lt;name&gt;</code>。
 * <p>
 * <strong>场景：</strong>
 * 当用户提供的是进程名（如 "com.android.phone" 或 "WhatsApp"）而非 PID，且目标应用已经在运行时使用。
 */
public final class AttachNameRunMode implements FridaRunMode {

    /** 进程名称 */
    private final @NotNull String name;

    /**
     *  AttachNameRunMode 构造函数用于初始化进程名称。
     * @param name
     */
    public AttachNameRunMode(@NotNull String name) {
        this.name = name;
    }

    /**
     * 获取进程名称。
     */
    public @NotNull String getName() {
        return name;
    }

    /**
     * 返回该运行模式的字符串表示形式，格式为 "Attach(-N &lt;name&gt;)"。
     */
    @Override
    public String toString() {
        return "Attach(-N " + name + ")";
    }
}
