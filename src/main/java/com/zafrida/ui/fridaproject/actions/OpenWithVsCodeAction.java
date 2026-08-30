package com.zafrida.ui.fridaproject.actions;

import com.intellij.ide.IdeView;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.actionSystem.LangDataKeys;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.psi.PsiDirectory;
import com.zafrida.ui.util.ZaFridaNotifier;
import com.zafrida.ui.util.ZaFridaVsCodeUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public final class OpenWithVsCodeAction extends AnAction {

    @Override
    public void update(@NotNull AnActionEvent e) {
        VirtualFile vf = resolveSelectedVirtualFile(e);
        boolean enabled = vf != null && vf.isInLocalFileSystem();
        e.getPresentation().setVisible(true);
        e.getPresentation().setEnabled(enabled);
    }

    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        Project project = e.getProject();
        if (project == null) {
            return;
        }

        VirtualFile vf = resolveSelectedVirtualFile(e);
        if (vf == null) {
            return;
        }

        if (!vf.isInLocalFileSystem()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Only local files/folders can be opened in VS Code");
            return;
        }

        ZaFridaVsCodeUtil.openPathInVsCodeAsync(project, vf.getPath());
    }

    private static @Nullable VirtualFile resolveSelectedVirtualFile(@NotNull AnActionEvent e) {
        VirtualFile vf = e.getData(CommonDataKeys.VIRTUAL_FILE);
        if (vf != null) {
            return vf;
        }

        VirtualFile[] files = e.getData(CommonDataKeys.VIRTUAL_FILE_ARRAY);
        if (files != null && files.length > 0) {
            return files[0];
        }

        IdeView ideView = e.getData(LangDataKeys.IDE_VIEW);
        if (ideView != null) {
            PsiDirectory[] dirs = ideView.getDirectories();
            if (dirs.length > 0) {
                return dirs[0].getVirtualFile();
            }
        }

        return null;
    }
}
