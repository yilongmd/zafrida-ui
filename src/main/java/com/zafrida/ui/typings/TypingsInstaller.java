package com.zafrida.ui.typings;

import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.fileEditor.FileEditorManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VfsUtil;
import com.intellij.openapi.vfs.VirtualFile;
import com.zafrida.ui.util.ZaFridaNotifier;
import org.jetbrains.annotations.NotNull;

import java.nio.charset.StandardCharsets;
/**
 * [辅助工具] Frida 智能补全安装器。
 * <p>
 * <strong>功能：</strong>
 * 在项目根目录下创建 {@code .zafrida/typings/frida-gum.d.ts} 文件。
 * <p>
 * <strong>目的：</strong>
 * 利用 IntelliJ/PyCharm 对 TypeScript 定义文件 (.d.ts) 的原生支持，
 * 为 JavaScript 编辑器提供 {@code Java.use}, {@code Interceptor.attach} 等 Frida API 的代码补全和参数提示。
 */
public final class TypingsInstaller {

    private TypingsInstaller() {
    }

    public static void install(@NotNull Project project) {
        String basePath = project.getBasePath();
        if (basePath == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Project basePath is null (can't install typings)");
            return;
        }

        WriteCommandAction.runWriteCommandAction(project, () -> {
            try {
                VirtualFile baseDir = VfsUtil.findFileByIoFile(new java.io.File(basePath), true);
                if (baseDir == null) {
                    ZaFridaNotifier.warn(project, "ZAFrida", "Cannot resolve project base dir");
                    return;
                }

                VirtualFile zafridaDir = VfsUtil.createDirectoryIfMissing(baseDir, ".zafrida");
                VirtualFile typingsDir = VfsUtil.createDirectoryIfMissing(zafridaDir, "typings");

                VirtualFile dts = typingsDir.findChild("frida-gum.d.ts");
                if (dts == null) {
                    dts = typingsDir.createChildData(TypingsInstaller.class, "frida-gum.d.ts");
                }

                VfsUtil.saveText(dts, DTS);
                dts.setCharset(StandardCharsets.UTF_8);
                dts.refresh(false, false);

                FileEditorManager.getInstance(project).openFile(dts, true);
                ZaFridaNotifier.info(project, "ZAFrida", "Installed typings: .zafrida/typings/frida-gum.d.ts");
            } catch (Throwable t) {
                ZaFridaNotifier.error(project, "ZAFrida", "Install typings failed: " + t.getMessage());
            }
        });
    }

    // NOTE: This is intentionally a minimal subset.
    private static final String DTS = """
            // Minimal Frida Gum typings for code completion (ZAFrida)
            // You can replace this file with @types/frida-gum for full coverage.

            declare const Java: {
              available: boolean;
              perform(fn: () => void): void;
              use(className: string): any;
              enumerateLoadedClassesSync(): string[];
            };

            declare const ObjC: {
              available: boolean;
              classes: any;
              Object: any;
              selectorAsString(sel: NativePointer): string;
            };

            declare const Interceptor: {
              attach(target: NativePointer, callbacks: {
                onEnter?(args: NativePointer[]): void;
                onLeave?(retval: NativePointer): void;
              }): void;
            };

            declare const Module: {
              findExportByName(module: string | null, name: string): NativePointer | null;
            };

            declare const Memory: {
              readUtf8String(ptr: NativePointer, length?: number): string;
            };

            declare function hexdump(target: NativePointer, options?: any): string;

            interface NativePointer {
              toString(): string;
            }
            """;
}
