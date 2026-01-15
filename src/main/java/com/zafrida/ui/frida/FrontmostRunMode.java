package com.zafrida.ui.frida;
/**
 * [运行模式] 附加到当前前台应用 (Frontmost)。
 * <p>
 * <strong>映射关系：</strong>
 * 对应 frida 命令行参数 <code>-F</code>。
 * <p>
 * <strong>逆向场景：</strong>
 * 快速调试当前屏幕上正在运行的应用，或者在使用 Frida Gadget 模式时（Gadget 通常监听并等待 -F 连接）。
 * 无需知道具体的 PID 或包名。
 */
public final class FrontmostRunMode implements FridaRunMode {
}
