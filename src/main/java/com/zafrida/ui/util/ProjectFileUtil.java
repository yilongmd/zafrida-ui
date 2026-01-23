package com.zafrida.ui.util;

import com.intellij.ide.projectView.ProjectView;
import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.fileChooser.FileChooser;
import com.intellij.openapi.fileChooser.FileChooserDescriptor;
import com.intellij.openapi.fileChooser.FileChooserDescriptorFactory;
import com.intellij.openapi.fileEditor.FileEditorManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VfsUtil;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.psi.PsiFile;
import com.intellij.psi.PsiManager;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.File;
import java.nio.charset.StandardCharsets;
/**
 * [工具类] 项目文件操作助手。
 * <p>
 * <strong>核心功能：</strong>
 * 1. 弹出文件选择器供用户选择 JS 脚本。
 * 2. 在 {@link WriteCommandAction} 中安全地创建文件和目录。
 * 3. 确保所有文件操作都通过 IntelliJ 的 VFS (Virtual File System) 进行，保证 IDE 索引同步。
 */
public final class ProjectFileUtil {

    /**
     * 私有构造函数，禁止实例化。
     */
    private ProjectFileUtil() {
    }

    /**
     * 弹出文件选择器选择 JS 脚本。
     * @param project 当前 IDE 项目
     * @return 选择的文件或 null
     */
    public static @Nullable VirtualFile chooseJavaScriptFile(@NotNull Project project) {
        FileChooserDescriptor descriptor = FileChooserDescriptorFactory.createSingleFileDescriptor("js");
        descriptor.setTitle("Select Frida JS Script");
        descriptor.setDescription("Select a JavaScript file inside your project");

        return FileChooser.chooseFile(descriptor, project, null);
    }

    /**
     * 在项目内弹出文件选择器选择 JS 脚本。
     * @param project 当前 IDE 项目
     * @param initialDir 初始目录（可为空）
     * @return 选择的文件或 null
     */
    public static @Nullable VirtualFile chooseJavaScriptFileInProject(@NotNull Project project,
                                                                      @Nullable VirtualFile initialDir) {
        FileChooserDescriptor descriptor = FileChooserDescriptorFactory.createSingleFileDescriptor("js");
        descriptor.setTitle("Select Frida JS Script");
        descriptor.setDescription("Select a JavaScript file inside your project");
        descriptor.setForcedToUseIdeaFileChooser(true);

        VirtualFile base = project.getBaseDir();
        if (base != null) {
            descriptor.setRoots(base);
        }

        VirtualFile start = initialDir != null ? initialDir : base;
        return FileChooser.chooseFile(descriptor, project, start);
    }

    /**
     * 在项目内创建脚本文件。
     * @param project 当前 IDE 项目
     * @param relativePath 相对路径
     * @param content 文件内容
     * @return 创建的文件或 null
     */
    public static @Nullable VirtualFile createScript(@NotNull Project project,
                                                     @NotNull String relativePath,
                                                     @NotNull String content) {
        String basePath = project.getBasePath();
        if (basePath == null) return null;

        File baseDir = new File(basePath);
        if (!baseDir.exists()) return null;

        final VirtualFile[] out = new VirtualFile[1];

        WriteCommandAction.runWriteCommandAction(project, () -> {
            try {
                VirtualFile base = VfsUtil.findFileByIoFile(baseDir, true);
                if (base == null) return;

                String parentRel = relativePath;
                String fileName = relativePath;
                int idx = relativePath.lastIndexOf('/');
                if (idx >= 0) {
                    parentRel = relativePath.substring(0, idx);
                    fileName = relativePath.substring(idx + 1);
                } else {
                    parentRel = "";
                }

                VirtualFile parent = parentRel.isEmpty() ? base : VfsUtil.createDirectoryIfMissing(base, parentRel);
                if (parent == null) return;

                VirtualFile vf = parent.findChild(fileName);
                if (vf == null) {
                    vf = parent.createChildData(ProjectFileUtil.class, fileName);
                }
                VfsUtil.saveText(vf, content);
                vf.setCharset(StandardCharsets.UTF_8);
                vf.refresh(false, false);

                out[0] = vf;
                FileEditorManager.getInstance(project).openFile(vf, true);
            } catch (Throwable ignored) {
            }
        });

        return out[0];
    }

    /**
     * 打开文件并在 Project 视图中选中。
     * @param project 当前 IDE 项目
     * @param file 目标文件
     */
    public static void openAndSelectInProject(@NotNull Project project, @NotNull VirtualFile file) {
        FileEditorManager.getInstance(project).openFile(file, true);
        ProjectView view = ProjectView.getInstance(project);
        PsiFile psiFile = PsiManager.getInstance(project).findFile(file);
        if (psiFile != null) {
            view.selectPsiElement(psiFile, true);
        } else {
            view.select(null, file, true);
        }
    }
}
