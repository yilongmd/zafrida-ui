package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;
/**
 * [代码片段] 插入标准的 Java 方法 Hook 模板。
 * <p>
 * <strong>生成结构：</strong>
 * <pre>
 * Java.perform(function() {
 * var c = Java.use("...");
 * c.method.overload(...).implementation = function(...) { ... }
 * });
 * </pre>
 * <strong>用途：</strong> 快速生成针对特定 Java 方法的 Hook 代码，包含参数打印和原始方法调用 ({@code this.method(arg)})。
 */
public class InsertJavaHookMethodAction extends InsertFridaSnippetAction {
    private static final @NotNull String SNIPPET = String.join("\n",
            """
                    Java.perform(function () {
                      var clazz = Java.use("com.example.ClassName");
                      clazz.method.overload("java.lang.String").implementation = function (arg) {
                        console.log("method called:", arg);
                        return this.method(arg);
                      };
                    });
                    """
    );

    public InsertJavaHookMethodAction() {
        super("Frida: hook Java method", SNIPPET);
    }
}
