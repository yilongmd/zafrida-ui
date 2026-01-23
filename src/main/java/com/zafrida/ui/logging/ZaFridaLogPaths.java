package com.zafrida.ui.logging;

import com.intellij.openapi.application.ApplicationManager;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
/**
 * [工具类] 日志文件路径生成策略。
 * <p>
 * <strong>命名规范：</strong>
 * {@code zafrida_{packageName}_{timestamp}.log}
 * <p>
 * <strong>存储位置：</strong>
 * 优先存储在 ZAFrida 子项目目录下，如果未指定则存储在 IDE 项目根目录的 {@code zafrida-logs/} 文件夹中。
 */
public final class ZaFridaLogPaths {

    /** 时间戳格式化器 */
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    private ZaFridaLogPaths() {
    }

    /**
     * 确保日志目录存在（在指定基础路径下）
     */
    public static @Nullable Path ensureLogsDir(@NotNull String basePath) {
        ZaFridaSettingsService settings = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
        String dirName = settings.getState().logsDirName;
        if (dirName == null || dirName.isBlank()) dirName = "zafrida-logs";
        try {
            Path dir = Paths.get(basePath, dirName);
            Files.createDirectories(dir);
            return dir;
        } catch (Throwable ignored) {
            return null;
        }
    }

    /**
     * 在项目根目录创建日志文件（无包名）
     */
    public static @Nullable Path newSessionLogFile(@NotNull String projectBasePath) {
        return newSessionLogFile(projectBasePath, null, null);
    }

    /**
     * 创建带包名的日志文件
     *
     * @param projectBasePath IDE 项目根目录
     * @param fridaProjectDir Frida 项目目录（可选，如果为空则使用项目根目录）
     * @param packageName     目标应用包名（可选，如果为空则不包含在文件名中）
     */
    public static @Nullable Path newSessionLogFile(@NotNull String projectBasePath,
                                                   @Nullable String fridaProjectDir,
                                                   @Nullable String packageName) {
        // 确定日志目录基础路径：优先使用 Frida 项目目录
        String basePath = (fridaProjectDir != null && !fridaProjectDir.isBlank())
                ? fridaProjectDir
                : projectBasePath;

        Path dir = ensureLogsDir(basePath);
        if (dir == null) return null;

        // 构建文件名：zafrida_{packageName}_{timestamp}.log 或 zafrida_{timestamp}.log
        String timestamp = LocalDateTime.now().format(FMT);
        String name;
        if (packageName != null && !packageName.isBlank()) {
            // 清理包名中的非法字符
            String safePackageName = sanitizeFileName(packageName);
            name = "zafrida_" + safePackageName + "_" + timestamp + ".log";
        } else {
            name = "zafrida_" + timestamp + ".log";
        }

        Path file = dir.resolve(name);
        try {
            if (!Files.exists(file)) {
                Files.createFile(file);
            }
        } catch (Throwable ignored) {
            // ignore
        }
        return file;
    }

    /**
     * 清理文件名中的非法字符
     */
    private static @NotNull String sanitizeFileName(@NotNull String name) {
        // 只保留字母、数字、点、下划线、连字符
        return name.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
}