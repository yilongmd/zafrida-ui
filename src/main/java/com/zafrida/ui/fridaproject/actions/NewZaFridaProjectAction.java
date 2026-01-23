package com.zafrida.ui.fridaproject.actions;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.project.Project;
import com.zafrida.ui.fridaproject.ZaFridaFridaProject;
import com.zafrida.ui.fridaproject.ZaFridaProjectManager;
import com.zafrida.ui.fridaproject.ZaFridaPlatform;
import com.zafrida.ui.fridaproject.ui.CreateZaFridaProjectDialog;
import com.zafrida.ui.util.ZaFridaNotifier;
/**
 * [Action] 创建新的 ZAFrida 项目。
 * <p>
 * <strong>流程：</strong>
 * 1. 弹出 {@link CreateZaFridaProjectDialog} 获取项目名和平台。
 * 2. 调用 {@link ZaFridaProjectManager#createAndActivate} 执行核心创建逻辑（创建目录、生成默认脚本、写入 XML）。
 * 3. 自动切换到新创建的项目。
 */
public final class NewZaFridaProjectAction extends AnAction {

    /**
     * 菜单执行逻辑。
     * @param e Action 事件
     */
    @Override
    public void actionPerformed(AnActionEvent e) {
        Project project = e.getProject();
        if (project == null) return;

        CreateZaFridaProjectDialog dialog = new CreateZaFridaProjectDialog(project);
        if (!dialog.showAndGet()) return;

        String name = dialog.getProjectName();
        if (name.isEmpty()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Project name is empty");
            return;
        }

        ZaFridaPlatform platform = dialog.getPlatform();
        try {
            ZaFridaProjectManager pm = project.getService(ZaFridaProjectManager.class);
            ZaFridaFridaProject created = pm.createAndActivate(name, platform);
            ZaFridaNotifier.info(project, "ZAFrida", "Created project: " + created.getName());
        } catch (Throwable t) {
            ZaFridaNotifier.error(project, "ZAFrida", "Create project failed: " + t.getMessage());
        }
    }
}
