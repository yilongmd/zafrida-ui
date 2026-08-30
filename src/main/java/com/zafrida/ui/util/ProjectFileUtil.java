package com.zafrida.ui.util;

import com.intellij.ide.projectView.ProjectView;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.fileChooser.FileChooser;
import com.intellij.openapi.fileChooser.FileChooserDescriptor;
import com.intellij.openapi.fileEditor.FileEditor;
import com.intellij.openapi.fileEditor.FileEditorManager;
import com.intellij.openapi.fileEditor.TextEditor;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.project.ProjectUtil;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.psi.PsiFile;
import com.intellij.psi.PsiManager;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;


public final class ProjectFileUtil {

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
        return new FileChooserDescriptor(true, false, false, false, false, false) {
            @Override
            public boolean isFileSelectable(@Nullable VirtualFile file) {
                return ProjectFileUtil.isFridaScriptFile(file);
            }
        };
    }

    public static void openAndSelectInProject(@NotNull Project project, @NotNull VirtualFile file) {
        if (!file.isDirectory()) {
            FileEditorManager.getInstance(project).openFile(file, true);
        }
        selectInProjectView(project, file);
    }

    public static void openAndSelectLogFileReadOnly(@NotNull Project project, @NotNull VirtualFile file) {
        if (!file.isDirectory()) {
            FileEditor[] editors = FileEditorManager.getInstance(project).openFile(file, true);
            for (FileEditor editor : editors) {
                if (editor instanceof TextEditor) {
                    Editor textEditor = ((TextEditor) editor).getEditor();
                    textEditor.getDocument().setReadOnly(true);
                }
            }
        }
        selectInProjectView(project, file);
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
