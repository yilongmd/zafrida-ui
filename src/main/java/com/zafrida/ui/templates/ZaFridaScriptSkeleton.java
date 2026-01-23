package com.zafrida.ui.templates;
/**
 * [常量] 默认的主脚本骨架。
 * <p>
 * <strong>AI 关键指令：</strong>
 * 必须包含 {@code //== ZAFrida:TEMPLATES:BEGIN ==} 和 {@code END} 标记。
 * {@link com.zafrida.ui.templates.TemplateScriptManipulator} 依赖这两个标记来定位插入区域。
 * 如果标记丢失，复选框注入功能将失效。
 */
public final class ZaFridaScriptSkeleton {

    /**
     * 私有构造函数，禁止实例化。
     */
    private ZaFridaScriptSkeleton() {
    }

    /** 默认脚本骨架内容 */
    public static final String TEXT = """
            'use strict';

            // ZAFrida Script Skeleton
            // Tips:
            // 1) Templates are managed by ZAFrida UI (checkbox -> insert/disable by comments)
            // 2) Do NOT delete markers unless you want to stop template management.

            function zlog(msg) {
              console.log("[ZAFrida] " + msg);
            }

            zlog("agent loaded");

            //== ZAFrida:TEMPLATES:BEGIN ==
            //== ZAFrida:TEMPLATES:END ==

            """;
}
