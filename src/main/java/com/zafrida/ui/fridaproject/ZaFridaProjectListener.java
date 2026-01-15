package com.zafrida.ui.fridaproject;

import org.jetbrains.annotations.Nullable;
/**
 * [监听器] ZAFrida 项目切换事件接口。
 * <p>
 * <strong>触发时机：</strong>
 * 当用户在 UI 中切换激活项目，或新创建项目时触发。
 * <p>
 * <strong>用途：</strong>
 * 通知 UI 组件（如 {@link com.zafrida.ui.ui.ZaFridaRunPanel}）刷新状态，加载新项目的配置（包名、脚本等）。
 */
public interface ZaFridaProjectListener {
    void onActiveProjectChanged(@Nullable ZaFridaFridaProject newProject);
}
