package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

/**
 * [代码片段] 插入 {@code Java.perform()} 基础包裹块。
 * <p>
 * <strong>逆向语义：</strong>
 * 这是 Android ART 运行时 Hook 的入口点。
 * 任何涉及 {@code Java.use}、{@code Java.choose} 或对象实例化的操作，都必须包裹在此回调中，
 * 以确保代码被附加到虚拟机的相关线程中执行。
 */
public class InsertJavaPerformAction extends InsertFridaSnippetAction {
    /** 内置代码片段 */
    private static final @NotNull String SNIPPET = String.join("\n",
            """
                    Java.perform(function () {
                      var Activity = Java.use("android.app.Activity");
                      console.log(Activity);
                    });
                    """
    );

    /**
     * 构造函数。
     */
    public InsertJavaPerformAction() {
        super("Frida: Java.perform block", SNIPPET);
    }
}
