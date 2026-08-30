package com.zafrida.ui.logging;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.diagnostic.Logger;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public final class ZaFridaLogPaths {

    private static final Logger LOG = Logger.getInstance(ZaFridaLogPaths.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss_SSS");
    public static final String DEFAULT_LOGS_DIR_NAME = "zafrida-logs";

    private ZaFridaLogPaths() {
    }

    public static @Nullable Path ensureLogsDir(@NotNull String basePath) {
        Path dir = resolveLogsDir(basePath);
        if (dir == null) {
            return null;
        }
        try {
            Files.createDirectories(dir);
            return dir;
        } catch (Throwable t) {
            LOG.warn(String.format("Create ZAFrida log directory failed: %s", dir), t);
            return null;
        }
    }

    public static @Nullable Path resolveLogsDir(@NotNull String basePath) {
        ZaFridaSettingsService settings = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
        String dirName = settings.getState().logsDirName;
        if (ZaStrUtil.isBlank(dirName)) {
            dirName = DEFAULT_LOGS_DIR_NAME;
        }
        try {
            Path base = Paths.get(basePath).toAbsolutePath().normalize();
            Path configured = Paths.get(dirName.trim());
            if (configured.isAbsolute()) {
                LOG.warn(String.format("Absolute log directory is not allowed; using %s: %s", DEFAULT_LOGS_DIR_NAME, configured));
                configured = Paths.get(DEFAULT_LOGS_DIR_NAME);
            }
            Path resolved = base.resolve(configured).normalize();
            if (!resolved.startsWith(base)) {
                LOG.warn(String.format("Log directory escapes the project; using %s: %s", DEFAULT_LOGS_DIR_NAME, configured));
                resolved = base.resolve(DEFAULT_LOGS_DIR_NAME);
            }
            return resolved;
        } catch (Throwable t) {
            LOG.warn(String.format("Resolve ZAFrida log directory failed: %s", basePath), t);
            return null;
        }
    }

    public static @Nullable Path newSessionLogFile(@NotNull String projectBasePath) {
        return newSessionLogFile(projectBasePath, null, null, "session");
    }

    public static @Nullable Path newSessionLogFile(@NotNull String projectBasePath,
                                                   @Nullable String fridaProjectDir,
                                                   @Nullable String packageName,
                                                   @NotNull String sessionTag) {
        String basePath = projectBasePath;
        if (ZaStrUtil.isNotBlank(fridaProjectDir)) {
            basePath = fridaProjectDir;
        }

        Path dir = ensureLogsDir(basePath);
        if (dir == null) {
            return null;
        }

        String timestamp = LocalDateTime.now().format(FMT);
        String safeSessionTag = sanitizeFileName(sessionTag);
        String name;
        if (ZaStrUtil.isNotBlank(packageName)) {
            String safePackageName = sanitizeFileName(packageName);
            name = String.format("zafrida_%s_%s_%s.log", timestamp, safePackageName, safeSessionTag);
        } else {
            name = String.format("zafrida_%s_%s.log", timestamp, safeSessionTag);
        }

        Path file = dir.resolve(name);
        try {
            int suffix = 2;
            while (Files.exists(file)) {
                String collisionName;
                if (ZaStrUtil.isNotBlank(packageName)) {
                    collisionName = String.format("zafrida_%s_%s_%s_%s.log",
                            timestamp, sanitizeFileName(packageName), safeSessionTag, suffix);
                } else {
                    collisionName = String.format("zafrida_%s_%s_%s.log", timestamp, safeSessionTag, suffix);
                }
                file = dir.resolve(collisionName);
                suffix++;
            }
            Files.createFile(file);
        } catch (Throwable t) {
            LOG.warn(String.format("Create ZAFrida log file failed: %s", file), t);
            return null;
        }
        return file;
    }

    private static @NotNull String sanitizeFileName(@NotNull String name) {
        return name.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
}
