package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;
/**
 * [代码片段] 插入 Native 层 {@code Interceptor.attach} 模板。
 * <p>
 * <strong>逆向语义：</strong>
 * 用于 Hook C/C++ 层的导出函数（如 libc.so 的 open/read/write）。
 * 生成包含 {@code onEnter} (函数调用前，查看参数) 和 {@code onLeave} (函数返回后，查看返回值) 的标准监听结构。
 * <p>
 * <strong>依赖：</strong> 通常配合 {@code Module.findExportByName} 使用。
 */
public class InsertInterceptorAttachAction extends InsertFridaSnippetAction {
    /** 内置代码片段 */
    private static final @NotNull String SNIPPET = String.join("\n",
            """
                    Interceptor.attach(Module.findExportByName(null, "open"), {
                      onEnter: function (args) {
                        console.log("open called");
                      },
                      onLeave: function (retval) {
                        console.log("open ->", retval);
                      }
                    });
                    """
    );

    /**
     * 构造函数。
     */
    public InsertInterceptorAttachAction() {
        super("Frida: Interceptor.attach", SNIPPET);
    }
}
