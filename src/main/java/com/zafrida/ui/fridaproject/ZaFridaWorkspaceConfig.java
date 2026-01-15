package com.zafrida.ui.fridaproject;

import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;
/**
 * [DTO] ZAFrida 工作区配置模型。
 * <p>
 * <strong>数据流：</strong>
 * 映射到 IDE 根目录下的 {@code zafrida-workspace.xml} 文件。
 * <p>
 * <strong>职责：</strong>
 * 1. 维护当前 IDE 项目中所有已注册的 ZAFrida 子项目列表。
 * 2. 记录上次激活的项目 (Active Project)，以便 IDE 重启后自动恢复状态。
 */
public final class ZaFridaWorkspaceConfig {
    public static final int VERSION = 1;
    public @Nullable String lastSelected = null;
    public final List<ZaFridaFridaProject> projects = new ArrayList<>();
}
