package com.zafrida.ui.frida;
/**
 * [标记接口] Frida 运行模式策略的顶层抽象。
 * <p>
 * <strong>实现类：</strong>
 * <ul>
 * <li>{@link SpawnRunMode}: 对应 <code>-f</code> (冷启动)</li>
 * <li>{@link FrontmostRunMode}: 对应 <code>-F</code> (前台/Gadget)</li>
 * <li>{@link AttachPidRunMode}: 对应 <code>-p</code> (PID 附加)</li>
 * <li>{@link AttachNameRunMode}: 对应 <code>-n</code> (名称附加)</li>
 * </ul>
 * 用于在 {@link com.zafrida.ui.frida.FridaCliService} 中通过 {@code instanceof} 匹配具体的命令行构建策略。
 */
public interface FridaRunMode {
}
