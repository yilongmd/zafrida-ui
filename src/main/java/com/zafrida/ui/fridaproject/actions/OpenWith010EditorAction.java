package com.zafrida.ui.fridaproject.actions;

import com.intellij.ide.IdeView;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.CommonDataKeys;
import com.intellij.openapi.actionSystem.LangDataKeys;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.psi.PsiElement;
import com.intellij.psi.PsiDirectory;
import com.intellij.psi.PsiFile;
import com.zafrida.ui.util.ZaFrida010EditorUtil;
import com.zafrida.ui.util.ZaFridaNotifier;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public final class OpenWith010EditorAction extends AnAction {

    @Override
    public void update(@NotNull AnActionEvent e) {
        e.getPresentation().setVisible(true);
        // Project View 的文件 DataKey 不稳定，保持可点击并在执行阶段校验。
        e.getPresentation().setEnabled(true);
    }

    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        Project project = e.getProject();
        if (project == null) {
            return;
        }

        VirtualFile vf = resolveSelectedVirtualFile(e);
        if (vf == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "No file selected");
            return;
        }

        if (!vf.isInLocalFileSystem()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Only local files can be opened in 010 Editor");
            return;
        }
        if (vf.isDirectory()) {
            ZaFridaNotifier.warn(project, "ZAFrida", "010 Editor opens files only");
            return;
        }

        ZaFrida010EditorUtil.openFileIn010EditorAsync(project, vf.getPath());
    }

    private static @Nullable VirtualFile resolveSelectedVirtualFile(@NotNull AnActionEvent e) {
        // 某些 DataKey 返回所在目录，因此优先解析具体文件。
        VirtualFile dirCandidate = null;

        PsiFile psiFile = e.getData(CommonDataKeys.PSI_FILE);
        if (psiFile != null) {
            VirtualFile vf = psiFile.getVirtualFile();
            if (vf != null) {
                return vf;
            }
        }

        PsiElement element = e.getData(CommonDataKeys.PSI_ELEMENT);
        if (element instanceof PsiFile elementPsiFile) {
            VirtualFile vf = elementPsiFile.getVirtualFile();
            if (vf != null) {
                return vf;
            }
        }
        if (element instanceof PsiDirectory psiDir) {
            dirCandidate = psiDir.getVirtualFile();
        }

        VirtualFile vf = e.getData(CommonDataKeys.VIRTUAL_FILE);
        if (vf != null) {
            if (!vf.isDirectory()) {
                return vf;
            }
            if (dirCandidate == null) {
                dirCandidate = vf;
            }
        }

        VirtualFile[] files = e.getData(CommonDataKeys.VIRTUAL_FILE_ARRAY);
        if (files != null && files.length > 0) {
            for (VirtualFile f : files) {
                if (f != null && !f.isDirectory()) {
                    return f;
                }
            }
            if (dirCandidate == null) {
                dirCandidate = files[0];
            }
        }

        IdeView ideView = e.getData(LangDataKeys.IDE_VIEW);
        if (ideView != null) {
            PsiDirectory[] dirs = ideView.getDirectories();
            if (dirs.length > 0 && dirCandidate == null) {
                dirCandidate = dirs[0].getVirtualFile();
            }
        }

        return dirCandidate;
    }
}
