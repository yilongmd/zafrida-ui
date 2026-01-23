package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;
/**
 * [代码片段] 插入 Frida {@code send()} 消息发送代码。
 * <p>
 * <strong>用途：</strong>
 * 通过 Frida 的 IPC (进程间通信) 通道，向宿主（Python/Node.js 或本插件的控制台）发送结构化数据。
 * <p>
 * <strong>区别：</strong>
 * 相比 {@code console.log} (直接打印字符串)，{@code send} 支持发送 JSON 对象或二进制数据，
 * 适合传输需要宿主进一步处理的 Payload。
 */
public class InsertSendLogAction extends InsertFridaSnippetAction {
    /** 内置代码片段 */
    private static final @NotNull String SNIPPET = """
            send({ type: "log", payload: "hello from frida" });
            """;

    /**
     * 构造函数。
     */
    public InsertSendLogAction() {
        super("Frida: send log message", SNIPPET);
    }
}
