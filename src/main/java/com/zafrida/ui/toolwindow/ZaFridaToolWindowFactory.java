package com.zafrida.ui.toolwindow;

import com.intellij.openapi.project.DumbAware;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentFactory;
import com.zafrida.ui.ui.ZaFridaMainToolWindow;
import org.jetbrains.annotations.NotNull;
/**
 * [入口点] IntelliJ ToolWindow 工厂类。
 * <p>
 * <strong>职责：</strong>
 * 插件启动时被 IDE 调用，负责实例化主界面 {@link ZaFridaMainToolWindow} 并将其挂载到 IDE 的侧边栏 (Tool Window Bar)。
 * 实现了 {@link DumbAware} 接口，意味着即使 IDE 正在构建索引，插件窗口也能正常显示。
 */
public final class ZaFridaToolWindowFactory implements ToolWindowFactory, DumbAware {

    /**
     * 创建并挂载 ToolWindow 内容。
     * @param project 当前 IDE 项目
     * @param toolWindow ToolWindow 实例
     */
    @Override
    public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow toolWindow) {
        ZaFridaMainToolWindow mainPanel = new ZaFridaMainToolWindow(project);

        Content content = ContentFactory.getInstance().createContent(mainPanel, "", false);
        toolWindow.getContentManager().addContent(content);
    }
}
