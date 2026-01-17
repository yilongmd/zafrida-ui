package com.zafrida.ui.fridaproject.actions;

import com.intellij.ide.IdeView;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.actionSystem.LangDataKeys;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.text.StringUtil;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.openapi.wm.ToolWindowManager;
import com.intellij.pom.Navigatable;
import com.intellij.psi.PsiDirectory;
import com.intellij.psi.PsiElement;
import com.intellij.util.SlowOperations;
import com.zafrida.ui.fridaproject.ZaFridaFridaProject;
import com.zafrida.ui.fridaproject.ZaFridaProjectConfig;
import com.zafrida.ui.fridaproject.ZaFridaProjectFiles;
import com.zafrida.ui.fridaproject.ZaFridaProjectManager;
import com.zafrida.ui.util.ZaFridaNotifier;

import java.util.Arrays;
import java.util.Comparator;
/**
 * [Action] 从文件夹加载现有项目。
 * <p>
 * <strong>场景：</strong>
 * 当用户手动复制了一个项目文件夹，或者在另一台机器上打开 IDE 时，
 * 通过右键点击文件夹将其“导入”并注册到 {@code zafrida-workspace.xml} 中。
 */
public final class LoadZaFridaProjectFromFolderAction extends AnAction {

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

        ZaFridaProjectManager pm = project.getService(ZaFridaProjectManager.class);
        VirtualFile configFile = dir.findChild(ZaFridaProjectFiles.PROJECT_FILE);
        if (configFile == null || configFile.isDirectory()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Load failed: zafrida-project.xml not found in folder");
            return;
        }

        ZaFridaFridaProject existing = pm.findProjectByDir(dir);
        if (existing != null) {
            ZaFridaNotifier.info(project, "ZAFrida", "Project already loaded: " + existing.getName());
            activateToolWindow(project);
            return;
        }

        ZaFridaFridaProject loaded = pm.registerExistingProject(dir, false);
        if (loaded == null) {
            ZaFridaNotifier.error(project, "ZAFrida", "Load failed: project folder is not under IDE root");
            return;
        }

        ensureDefaultMainScript(pm, loaded, dir);

        project.getMessageBus().syncPublisher(ZaFridaProjectManager.TOPIC)
                .onActiveProjectChanged(pm.getActiveProject());

        ZaFridaNotifier.info(project, "ZAFrida", "Loaded Frida project: " + loaded.getName());
        activateToolWindow(project);
    }

    private static void activateToolWindow(Project project) {
        var tw = ToolWindowManager.getInstance(project).getToolWindow("ZAFrida");
        if (tw != null) tw.activate(null);
    }

    private static void ensureDefaultMainScript(ZaFridaProjectManager pm,
                                                ZaFridaFridaProject project,
                                                VirtualFile dir) {
        ZaFridaProjectConfig cfg = pm.loadProjectConfig(project);
        if (hasValidMainScript(dir, cfg)) return;

        String picked = pickDefaultMainScript(dir);
        String updated = picked == null ? "" : picked;
        if (!updated.equals(cfg.mainScript)) {
            pm.updateProjectConfig(project, c -> c.mainScript = updated);
        }
    }

    private static boolean hasValidMainScript(VirtualFile dir, ZaFridaProjectConfig cfg) {
        if (StringUtil.isEmptyOrSpaces(cfg.mainScript)) return false;
        final VirtualFile[] ref = new VirtualFile[1];
        SlowOperations.allowSlowOperations(() -> ref[0] = dir.findFileByRelativePath(cfg.mainScript));
        return ref[0] != null && !ref[0].isDirectory();
    }

    private static String pickDefaultMainScript(VirtualFile dir) {
        String sameName = ZaFridaProjectFiles.defaultMainScriptName(dir.getName());
        VirtualFile match = dir.findChild(sameName);
        if (match != null && !match.isDirectory()) return sameName;

        VirtualFile agent = dir.findChild(ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT);
        if (agent != null && !agent.isDirectory()) return ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT;

        final VirtualFile[][] childrenRef = new VirtualFile[1][];
        SlowOperations.allowSlowOperations(() -> childrenRef[0] = dir.getChildren());
        VirtualFile[] children = childrenRef[0];
        if (children == null || children.length == 0) return null;

        Arrays.sort(children, Comparator.comparing(VirtualFile::getName, String.CASE_INSENSITIVE_ORDER));
        for (VirtualFile child : children) {
            if (!child.isDirectory() && "js".equalsIgnoreCase(child.getExtension())) {
                return child.getName();
            }
        }
        return null;
    }
}
