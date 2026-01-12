package com.zafrida.ui.templates;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.text.StringUtil;
import com.zafrida.ui.fridaproject.ZaFridaPlatform;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class ZaFridaTemplateFileStore {

    private static final String TEMPLATE_ROOT = ".zafrida/templates";

    private ZaFridaTemplateFileStore() {
    }

    public static @NotNull List<ZaFridaTemplateFile> load(@NotNull Project project,
                                                         @NotNull ZaFridaPlatform platform) {
        Path dir = resolveTemplatesDir(project, platform);
        if (dir == null) return List.of();
        ensureDefaults(dir, platform);

        List<ZaFridaTemplateFile> out = new ArrayList<>();
        try {
            Files.createDirectories(dir);
            try (var stream = Files.list(dir)) {
                stream.filter(path -> path.getFileName().toString().endsWith(".js"))
                        .sorted(Comparator.comparing(path -> path.getFileName().toString().toLowerCase(Locale.ROOT)))
                        .forEach(path -> {
                            String content = readFile(path);
                            if (content == null) return;
                            String fileName = stripExtension(path.getFileName().toString());
                            String id = fileName;
                            String title = prettifyTitle(fileName);
                            ZaFridaTemplateCategory category = platform == ZaFridaPlatform.IOS
                                    ? ZaFridaTemplateCategory.IOS
                                    : ZaFridaTemplateCategory.ANDROID;
                            ZaFridaTemplate t = new ZaFridaTemplate(
                                    id,
                                    title,
                                    "Template file: " + path.getFileName(),
                                    category,
                                    content
                            );
                            out.add(new ZaFridaTemplateFile(t, path));
                        });
            }
        } catch (IOException ignore) {
        }
        return out;
    }

    public static @Nullable Path resolveTemplatesDir(@NotNull Project project,
                                                     @NotNull ZaFridaPlatform platform) {
        String base = project.getBasePath();
        if (base == null) return null;
        String platformDir = platform == ZaFridaPlatform.IOS ? "ios" : "android";
        return Path.of(base, TEMPLATE_ROOT, platformDir);
    }

    public static @Nullable Path createTemplate(@NotNull Project project,
                                                @NotNull ZaFridaPlatform platform,
                                                @NotNull String name) {
        Path dir = resolveTemplatesDir(project, platform);
        if (dir == null) return null;
        String fileName = normalizeFileName(name) + ".js";
        Path file = dir.resolve(fileName);
        if (Files.exists(file)) return file;
        try {
            Files.createDirectories(dir);
            Files.writeString(file, defaultTemplateContent(name), StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE_NEW);
            return file;
        } catch (IOException ignore) {
            return null;
        }
    }

    public static boolean deleteTemplate(@NotNull Path path) {
        try {
            return Files.deleteIfExists(path);
        } catch (IOException ignore) {
            return false;
        }
    }

    private static void ensureDefaults(@NotNull Path dir, @NotNull ZaFridaPlatform platform) {
        Map<String, String> defaults = defaultTemplatesFor(platform);
        for (Map.Entry<String, String> entry : defaults.entrySet()) {
            Path file = dir.resolve(entry.getKey() + ".js");
            if (Files.exists(file)) continue;
            try {
                Files.createDirectories(dir);
                Files.writeString(file, entry.getValue(), StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE_NEW);
            } catch (IOException ignore) {
            }
        }
    }

    private static Map<String, String> defaultTemplatesFor(@NotNull ZaFridaPlatform platform) {
        Map<String, String> out = new LinkedHashMap<>();
        if (platform == ZaFridaPlatform.IOS) {
            out.put("ios_objc_available", """
                    if (ObjC.available) {
                      console.log("[iOS] ObjC is available");
                      // TODO: your hooks here
                    } else {
                      console.log("[iOS] ObjC is not available");
                    }
                    """.strip());
        } else {
            out.put("android_java_perform", """
                    if (Java.available) {
                      Java.perform(function () {
                        console.log("[Android] Java.perform() entered");
                        // TODO: your hooks here
                      });
                    } else {
                      console.log("[Android] Java is not available");
                    }
                    """.strip());
            out.put("android_hook_method", """
                    if (Java.available) {
                      Java.perform(function () {
                        var ClzName = "java.lang.String";
                        var Clz = Java.use(ClzName);
                        // Example: hook String.length()
                        Clz.length.implementation = function () {
                          var ret = this.length();
                          console.log("[Hook] " + ClzName + ".length() => " + ret);
                          return ret;
                        };
                      });
                    }
                    """.strip());
        }
        return out;
    }

    private static String defaultTemplateContent(@NotNull String name) {
        return "// ZAFrida Template: " + name + "\n";
    }

    private static @Nullable String readFile(@NotNull Path path) {
        try {
            return Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException ignore) {
            return null;
        }
    }

    private static String stripExtension(@NotNull String name) {
        int idx = name.lastIndexOf('.');
        return idx > 0 ? name.substring(0, idx) : name;
    }

    private static String normalizeFileName(@NotNull String input) {
        String name = input.trim().replaceAll("[\\\\/:*?\"<>|]", "_");
        return name.isEmpty() ? "new_template" : name;
    }

    private static String prettifyTitle(@NotNull String fileName) {
        String[] parts = fileName.replace('-', ' ').replace('_', ' ').split("\\s+");
        List<String> words = new ArrayList<>();
        for (String part : parts) {
            if (part.isBlank()) continue;
            words.add(StringUtil.capitalize(part.toLowerCase(Locale.ROOT)));
        }
        return words.isEmpty() ? fileName : String.join(" ", words);
    }
}
