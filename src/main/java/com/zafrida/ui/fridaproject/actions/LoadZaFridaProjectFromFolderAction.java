package com.zafrida.ui.fridaproject.actions;

import com.intellij.openapi.actionSystem.*;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.openapi.wm.ToolWindowManager;
import com.zafrida.ui.fridaproject.ZaFridaProjectManager;

public final class LoadZaFridaProjectFromFolderAction extends AnAction {

    @Override
    public void update(AnActionEvent e) {
        VirtualFile vf = e.getData(CommonDataKeys.VIRTUAL_FILE);
        boolean ok = vf != null && vf.isDirectory();
        e.getPresentation().setEnabledAndVisible(ok);
    }

    @Override
    public void actionPerformed(AnActionEvent e) {
        Project project = e.getProject();
        VirtualFile dir = e.getData(CommonDataKeys.VIRTUAL_FILE);
        if (project == null || dir == null || !dir.isDirectory()) return;

        ZaFridaProjectManager pm = project.getService(ZaFridaProjectManager.class);

        // 简化：通过目录名推断为 Frida 项目（你也可以要求存在 zafrida-project.xml 才识别）
        // 推荐规则：android/<name> 或 ios/<name>
        String path = dir.getPath().replace('\\','/');
        String base = project.getBasePath();
        if (base == null) return;
        String bp = base.replace('\\','/');
        if (!path.startsWith(bp)) return;
        String rel = path.substring(bp.length());
        if (rel.startsWith("/")) rel = rel.substring(1);

        // rel = android/XXX or ios/XXX
        // 直接刷新 manager 的 workspace：更严格可在这里“导入”逻辑项目
        pm.reload();
        // 如果 workspace 里已存在同名项目就切换，否则你可以扩展一个 importExisting(dir) 自动写入 workspace
        // 这里先激活：让 UI 收到事件
        pm.setActiveProject(pm.getActiveProject()); // 触发一次刷新也行

        // 激活 ToolWindow
        var tw = ToolWindowManager.getInstance(project).getToolWindow("ZAFrida");
        if (tw != null) tw.activate(null);
    }
}
