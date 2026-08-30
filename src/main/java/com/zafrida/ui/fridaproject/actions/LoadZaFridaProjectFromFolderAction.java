package com.zafrida.ui.fridaproject.actions;

import com.intellij.ide.IdeView;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.actionSystem.LangDataKeys;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowManager;
import com.intellij.psi.PsiDirectory;
import com.zafrida.ui.fridaproject.ZaFridaProjectFiles;
import com.zafrida.ui.fridaproject.ZaFridaProjectManager;
import com.zafrida.ui.util.ZaFridaNotifier;

public final class LoadZaFridaProjectFromFolderAction extends AnAction {

    @Override
    public void update(AnActionEvent e) {
        VirtualFile vf = null;

        // Project View 下 IDE_VIEW 比 VIRTUAL_FILE 更稳定。
        IdeView ideView = e.getData(LangDataKeys.IDE_VIEW);
        if (ideView != null) {
            PsiDirectory[] dirs = ideView.getDirectories();
            if (dirs.length > 0) {
                vf = dirs[0].getVirtualFile();
            }
        }

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
        if (project == null) {
            return;
        }

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

        if (dir == null || !dir.isDirectory()) {
            return;
        }

        ZaFridaProjectManager pm = project.getService(ZaFridaProjectManager.class);
        VirtualFile finalDir = dir;
        VirtualFile finalDir1 = dir;
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            VirtualFile configFile = finalDir.findChild(ZaFridaProjectFiles.PROJECT_FILE);
            if (configFile == null || configFile.isDirectory()) {
                ApplicationManager.getApplication().invokeLater(() ->
                        ZaFridaNotifier.warn(project, "ZAFrida", "Load failed: zafrida-project.xml not found in folder"));
                return;
            }

            pm.findProjectByDirAsync(finalDir, existing -> {
                if (existing != null) {
                    ZaFridaNotifier.info(project, "ZAFrida", String.format("Project already loaded: %s", existing.getName()));
                    activateToolWindow(project);
                    return;
                }

                pm.registerExistingProjectAsync(finalDir1, false, loaded -> {
                    if (loaded == null) {
                        ZaFridaNotifier.error(project, "ZAFrida", "Load failed: project folder is not under IDE root");
                        return;
                    }

                    pm.ensureDefaultMainScriptAsync(loaded, () -> {
                        project.getMessageBus().syncPublisher(ZaFridaProjectManager.TOPIC)
                                .onActiveProjectChanged(pm.getActiveProject());
                        ZaFridaNotifier.info(project, "ZAFrida", String.format("Loaded Frida project: %s", loaded.getName()));
                        activateToolWindow(project);
                    });
                });
            });
        });
    }

    private static void activateToolWindow(Project project) {
        ToolWindow toolWindow = ToolWindowManager.getInstance(project).getToolWindow("ZAFrida");
        if (toolWindow != null) {
            toolWindow.activate(null);
        }
    }

}
