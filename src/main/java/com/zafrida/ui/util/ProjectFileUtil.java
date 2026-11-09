package com.zafrida.ui.util;

import com.intellij.ide.projectView.ProjectView;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.application.ReadAction;
import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.fileChooser.FileChooser;
import com.intellij.openapi.fileChooser.FileChooserDescriptor;
import com.intellij.openapi.fileEditor.FileDocumentManager;
import com.intellij.openapi.fileEditor.OpenFileDescriptor;
import com.intellij.openapi.progress.ProcessCanceledException;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.project.ProjectUtil;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.psi.PsiFile;
import com.intellij.psi.PsiManager;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public final class ProjectFileUtil {

    private static final Logger LOG = Logger.getInstance(ProjectFileUtil.class);

    private ProjectFileUtil() {
    }

    public static @Nullable VirtualFile chooseFridaScriptFile(@NotNull Project project,
                                                              @Nullable VirtualFile initialSelection) {
        FileChooserDescriptor descriptor = createFridaScriptDescriptor();
        descriptor.setTitle("Select Frida Script");
        descriptor.setDescription("Select a JavaScript or TypeScript file");

        return FileChooser.chooseFile(descriptor, project, initialSelection);
    }

    public static @Nullable VirtualFile chooseFridaScriptFileInProject(@NotNull Project project,
                                                                       @Nullable VirtualFile initialDir) {
        FileChooserDescriptor descriptor = createFridaScriptDescriptor();
        descriptor.setTitle("Select Frida Script");
        descriptor.setDescription("Select a JavaScript or TypeScript file inside your project");
        descriptor.setForcedToUseIdeaFileChooser(true);

        VirtualFile base = ProjectUtil.guessProjectDir(project);
        if (base != null) {
            descriptor.setRoots(base);
        }

        VirtualFile start = base;
        if (initialDir != null && initialDir.isValid()) {
            start = initialDir;
        }
        return FileChooser.chooseFile(descriptor, project, start);
    }

    public static boolean isFridaScriptFile(@Nullable VirtualFile file) {
        if (file == null || file.isDirectory()) {
            return false;
        }
        String extension = file.getExtension();
        if (extension == null) {
            return false;
        }
        return "js".equalsIgnoreCase(extension) || "ts".equalsIgnoreCase(extension);
    }

    private static @NotNull FileChooserDescriptor createFridaScriptDescriptor() {
        // 2026.x 禁止覆写 isFileSelectable，过滤条件改由稳定的 descriptor API 提供。
        return new FileChooserDescriptor(true, false, false, false, false, false)
                .withFileFilter(ProjectFileUtil::isFridaScriptFile);
    }

    public static void openAndSelectInProject(@NotNull Project project, @NotNull VirtualFile file) {
        if (!file.isDirectory()) {
            // 2026.3 的同步 openFile 重载均已废弃，导航入口跨支持版本保持稳定。
            new OpenFileDescriptor(project, file).navigate(true);
        }
        selectInProjectView(project, file);
    }

    public static void openAndSelectLogFileReadOnly(@NotNull Project project, @NotNull VirtualFile file) {
        if (file.isDirectory()) {
            selectInProjectView(project, file);
            return;
        }
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                Document document = ReadAction.nonBlocking(() ->
                        FileDocumentManager.getInstance().getDocument(file)).executeSynchronously();
                ApplicationManager.getApplication().invokeLater(() -> {
                    if (project.isDisposed()) {
                        return;
                    }
                    if (!file.isValid()) {
                        ZaFridaNotifier.warn(project, "ZAFrida", String.format("Log file no longer exists: %s", file.getPath()));
                        return;
                    }
                    try {
                        if (document != null) {
                            WriteCommandAction.runWriteCommandAction(project, () -> document.setReadOnly(true));
                        }
                        new OpenFileDescriptor(project, file).navigate(true);
                        selectInProjectView(project, file);
                    } catch (RuntimeException e) {
                        reportOpenFailure(project, file, e);
                    }
                });
            } catch (ProcessCanceledException e) {
                throw e;
            } catch (RuntimeException e) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    if (!project.isDisposed()) {
                        reportOpenFailure(project, file, e);
                    }
                });
            }
        });
    }

    private static void reportOpenFailure(@NotNull Project project,
                                          @NotNull VirtualFile file,
                                          @NotNull RuntimeException error) {
        LOG.warn(String.format("Open ZAFrida log file failed: %s", file.getPath()), error);
        ZaFridaNotifier.error(project, "ZAFrida", String.format("Open log file failed: %s", file.getPath()));
    }

    private static void selectInProjectView(@NotNull Project project, @NotNull VirtualFile file) {
        ProjectView view = ProjectView.getInstance(project);
        PsiFile psiFile = PsiManager.getInstance(project).findFile(file);
        if (psiFile != null) {
            view.selectPsiElement(psiFile, true);
        } else {
            view.select(null, file, true);
        }
    }
}
