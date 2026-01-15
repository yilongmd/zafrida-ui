package com.zafrida.ui.frida;

/**
 * [枚举] Frida 连接模式定义。
 * <p>
 * <strong>映射关系：</strong>
 * <ul>
 * <li>{@code USB}: 对应 frida 命令行参数 <code>-U</code> (通过 USB 连接 Android/iOS)。</li>
 * <li>{@code REMOTE}: 对应 frida 命令行参数 <code>-H host:port</code> (连接到 frida-server)。</li>
 * <li>{@code GADGET}: 特殊模式，通常配合 <code>-H</code> 或 <code>-F</code> 使用，用于连接嵌入式 Gadget。</li>
 * </ul>
 */
public enum FridaConnectionMode {
    USB("USB"),
    REMOTE("Remote"),
    GADGET("Gadget");

    private final String displayName;

    FridaConnectionMode(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
