package com.zafrida.ui.editor.actions;

import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.fileEditor.FileDocumentManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VfsUtilCore;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowManager;
import com.intellij.ui.content.Content;
import com.zafrida.ui.fridaproject.ZaFridaFridaProject;
import com.zafrida.ui.fridaproject.ZaFridaProjectFiles;
import com.zafrida.ui.fridaproject.ZaFridaProjectManager;
import com.zafrida.ui.ui.ZaFridaMainToolWindow;
import com.zafrida.ui.ui.ZaFridaRunPanel;
import com.zafrida.ui.util.ZaFridaIcons;
import com.zafrida.ui.util.ZaFridaNotifier;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JComponent;

/**
 * [Action] 在编辑器中运行当前 Frida JS 脚本。
 * <p>
 * 自动切换到脚本所属的 ZAFrida 项目并触发 Run 面板运行。
 */
public final class RunFridaJsAction extends AnAction {

    /**
     * 构造函数，设置菜单图标。
     */
    public RunFridaJsAction() {
        getTemplatePresentation().setIcon(ZaFridaIcons.RUN_FRIDA);
    }

    /**
     * 菜单可用性更新逻辑。
     * @param e Action 事件
     */
    @Override
    public void update(@NotNull AnActionEvent e) {
        Project project = e.getProject();
        VirtualFile file = resolveScriptFile(e);
        boolean enabled = project != null && file != null && !file.isDirectory() && isJsFile(file);
        e.getPresentation().setVisible(true);
        e.getPresentation().setEnabled(enabled);
    }

    /**
     * 菜单执行逻辑。
     * @param e Action 事件
     */
    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        Project project = e.getProject();
        if (project == null) return;

        VirtualFile script = resolveScriptFile(e);
        if (script == null || script.isDirectory() || !isJsFile(script)) return;

        Editor editor = e.getData(CommonDataKeys.EDITOR);
        if (editor != null) {
            FileDocumentManager.getInstance().saveDocument(editor.getDocument());
        }

        ZaFridaProjectManager pm = project.getService(ZaFridaProjectManager.class);
        ZaFridaFridaProject previous = pm.getActiveProject();
        VirtualFile projectDir = findFridaProjectDir(project, script);
        if (projectDir == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "No Frida project found for this script");
            return;
        }

        ZaFridaFridaProject target = pm.findProjectByDir(projectDir);
        if (target == null) {
            target = pm.registerExistingProject(projectDir, true);
            if (target == null) {
                ZaFridaNotifier.warn(project, "ZAFrida", "Frida project is not under IDE root");
                return;
            }
        }

        boolean switching = previous == null || !previous.equals(target);
        if (!target.equals(pm.getActiveProject())) {
            pm.setActiveProject(target);
        }

        ToolWindow toolWindow = ToolWindowManager.getInstance(project).getToolWindow("ZAFrida");
        if (toolWindow == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "ZAFrida tool window not available");
            return;
        }

        Runnable runTask = () -> {
            ZaFridaRunPanel runPanel = findRunPanel(toolWindow);
            if (runPanel == null) {
                ZaFridaNotifier.warn(project, "ZAFrida", "ZAFrida run panel not initialized");
                return;
            }
            Runnable doRun = () -> runPanel.runWithRunScript(script);
            if (switching) {
                ApplicationManager.getApplication().invokeLater(doRun);
            } else {
                doRun.run();
            }
        };

        toolWindow.activate(runTask);
    }

    /**
     * 判断是否为 JavaScript 文件。
     * @param file 文件对象
     * @return true 表示为 JS 文件
     */
    private static boolean isJsFile(@NotNull VirtualFile file) {
        String ext = file.getExtension();
        return ext != null && ext.equalsIgnoreCase("js");
    }

    /**
     * 解析当前脚本文件。
     * @param e Action 事件
     * @return 脚本文件或 null
     */
    private static @Nullable VirtualFile resolveScriptFile(@NotNull AnActionEvent e) {
        VirtualFile file = e.getData(CommonDataKeys.VIRTUAL_FILE);
        if (file != null) return file;
        VirtualFile[] files = e.getData(CommonDataKeys.VIRTUAL_FILE_ARRAY);
        if (files != null && files.length > 0) return files[0];
        Editor editor = e.getData(CommonDataKeys.EDITOR);
        if (editor != null) {
            return FileDocumentManager.getInstance().getFile(editor.getDocument());
        }
        return null;
    }

    /**
     * 查找脚本所属的 Frida 项目目录。
     * @param project 当前 IDE 项目
     * @param file 脚本文件
     * @return 项目目录或 null
     */
    private static @Nullable VirtualFile findFridaProjectDir(@NotNull Project project, @NotNull VirtualFile file) {
        VirtualFile base = project.getBaseDir();
        if (base == null) return null;

        VirtualFile dir = file.isDirectory() ? file : file.getParent();
        while (dir != null && VfsUtilCore.isAncestor(base, dir, false)) {
            VirtualFile marker = dir.findChild(ZaFridaProjectFiles.PROJECT_FILE);
            if (marker != null && !marker.isDirectory()) {
                return dir;
            }
            if (dir.equals(base)) break;
            dir = dir.getParent();
        }
        return null;
    }

    /**
     * 在 ToolWindow 中查找 Run 面板。
     * @param toolWindow 工具窗口
     * @return Run 面板或 null
     */
    private static @Nullable ZaFridaRunPanel findRunPanel(@NotNull ToolWindow toolWindow) {
        Content[] contents = toolWindow.getContentManager().getContents();
        for (Content content : contents) {
            JComponent component = content.getComponent();
            if (component instanceof ZaFridaMainToolWindow main) {
                return main.getRunPanel();
            }
        }
        return null;
    }
}
