package com.zafrida.ui.fridaproject.actions;

import com.intellij.ide.IdeView;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.actionSystem.LangDataKeys;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.openapi.wm.ToolWindowManager;
import com.intellij.pom.Navigatable;
import com.intellij.psi.PsiDirectory;
import com.intellij.psi.PsiElement;
import com.zafrida.ui.fridaproject.ZaFridaFridaProject;
import com.zafrida.ui.fridaproject.ZaFridaProjectFiles;
import com.zafrida.ui.fridaproject.ZaFridaProjectManager;
import com.zafrida.ui.util.ZaFridaNotifier;

public final class SelectZaFridaProjectFromFolderAction extends AnAction {

    @Override
    public void update(AnActionEvent e) {
        VirtualFile vf = null;

        // 方法1：通过 IDE_VIEW 获取（ProjectView 右键菜单最可靠的方式）
        IdeView ideView = e.getData(LangDataKeys.IDE_VIEW);
        if (ideView != null) {
            PsiDirectory[] dirs = ideView.getDirectories();
            if (dirs.length > 0) {
                vf = dirs[0].getVirtualFile();
            }
        }

        // 方法2：fallback
        if (vf == null) {
            vf = e.getData(CommonDataKeys.VIRTUAL_FILE);
        }
        if (vf == null) {
            VirtualFile[] files = e.getData(CommonDataKeys.VIRTUAL_FILE_ARRAY);
            if (files != null && files.length > 0) {
                vf = files[0];
            }
        }

        boolean isDir = vf != null && vf.isDirectory();
        e.getPresentation().setVisible(true);
        e.getPresentation().setEnabled(isDir);
    }

    @Override
    public void actionPerformed(AnActionEvent e) {
        Project project = e.getProject();
        if (project == null) return;

        VirtualFile dir = null;

        IdeView ideView = e.getData(LangDataKeys.IDE_VIEW);
        if (ideView != null) {
            PsiDirectory[] dirs = ideView.getDirectories();
            if (dirs.length > 0) {
                dir = dirs[0].getVirtualFile();
            }
        }

        if (dir == null) {
            dir = e.getData(CommonDataKeys.VIRTUAL_FILE);
        }
        if (dir == null) {
            VirtualFile[] files = e.getData(CommonDataKeys.VIRTUAL_FILE_ARRAY);
            if (files != null && files.length > 0) {
                dir = files[0];
            }
        }

        if (dir == null || !dir.isDirectory()) return;

        VirtualFile configFile = dir.findChild(ZaFridaProjectFiles.PROJECT_FILE);
        if (configFile == null || configFile.isDirectory()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Select failed: zafrida-project.xml not found in folder");
            return;
        }

        ZaFridaProjectManager pm = project.getService(ZaFridaProjectManager.class);
        ZaFridaFridaProject target = pm.findProjectByDir(dir);
        if (target == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Project not loaded. Use Load Frida Project first.");
            return;
        }

        pm.setActiveProject(target);
        ZaFridaNotifier.info(project, "ZAFrida", "Selected Frida project: " + target.getName());
        activateToolWindow(project);
    }

    private static void activateToolWindow(Project project) {
        var tw = ToolWindowManager.getInstance(project).getToolWindow("ZAFrida");
        if (tw != null) tw.activate(null);
    }
}
