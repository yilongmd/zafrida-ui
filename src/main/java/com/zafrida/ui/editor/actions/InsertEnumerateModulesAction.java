package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;
/**
 * [代码片段] 插入模块枚举脚本 ({@code Process.enumerateModules})。
 * <p>
 * <strong>用途：</strong>
 * 遍历当前进程加载的所有动态链接库（.so / .dll / .dylib）。
 * <p>
 * <strong>逆向场景：</strong>
 * 1. 确定目标 so 文件的基址 (Base Address)，用于计算函数偏移。
 * 2. 验证 so 文件是否已被加载。
 * 3. 对抗 ASLR (地址空间布局随机化)。
 */
public class InsertEnumerateModulesAction extends InsertFridaSnippetAction {
    private static final @NotNull String SNIPPET = String.join("\n",
            """
                    Process.enumerateModules().forEach(function (m) {
                      console.log(m.name + " " + m.base);
                    });
                    """
    );

    public InsertEnumerateModulesAction() {
        super("Frida: enumerate modules", SNIPPET);
    }
}
