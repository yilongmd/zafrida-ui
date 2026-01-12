package com.zafrida.ui.templates;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.text.StringUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

public final class ZaFridaTemplateService {

    private final @NotNull Path templatesRoot;
    private final List<ZaFridaTemplate> templates = new ArrayList<>();

    public ZaFridaTemplateService(@NotNull Project project) {
        this.templatesRoot = resolveTemplatesRoot(project);
        ensureDefaultTemplates();
        reload();
    }

    public synchronized void reload() {
        templates.clear();
        templates.addAll(loadTemplatesFromDisk());
    }

    public synchronized @NotNull List<ZaFridaTemplate> all() {
        return new ArrayList<>(templates);
    }

    public synchronized @NotNull Optional<ZaFridaTemplate> findById(@NotNull String id) {
        for (ZaFridaTemplate t : templates) {
            if (t.getId().equals(id)) return Optional.of(t);
        }
        return Optional.empty();
    }

    public synchronized boolean addTemplate(@NotNull ZaFridaTemplateCategory category,
                                            @NotNull String fileName,
                                            @NotNull String content) {
        String baseName = normalizeFileBaseName(fileName);
        if (baseName.isEmpty()) return false;
        if (findById(baseName).isPresent()) return false;

        Path dir = templatesRoot.resolve(categoryDirName(category));
        Path target = dir.resolve(baseName + ".js");
        try {
            Files.createDirectories(dir);
            Files.writeString(target, content.stripTrailing() + System.lineSeparator(), StandardCharsets.UTF_8);
            reload();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public synchronized boolean deleteTemplate(@NotNull ZaFridaTemplate template) {
        Path path = template.getSourcePath();
        if (path == null) return false;
        try {
            Files.deleteIfExists(path);
            reload();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public @NotNull Path getTemplatesRoot() {
        return templatesRoot;
    }

    private @NotNull List<ZaFridaTemplate> loadTemplatesFromDisk() {
        List<ZaFridaTemplate> list = new ArrayList<>();
        for (ZaFridaTemplateCategory category : ZaFridaTemplateCategory.values()) {
            Path dir = templatesRoot.resolve(categoryDirName(category));
            if (!Files.isDirectory(dir)) continue;

            try (Stream<Path> stream = Files.list(dir)) {
                stream.filter(p -> p.getFileName().toString().toLowerCase().endsWith(".js"))
                        .sorted()
                        .forEach(path -> {
                            String baseName = stripExtension(path.getFileName().toString());
                            if (baseName.isEmpty()) return;
                            if (list.stream().anyMatch(t -> t.getId().equals(baseName))) return;
                            String content = readFile(path);
                            String title = prettifyTitle(baseName);
                            String description = "Template: " + baseName;
                            list.add(new ZaFridaTemplate(baseName, title, description, category, content, path));
                        });
            } catch (IOException ignored) {
                // ignore invalid folder
            }
        }
        return list;
    }

    private void ensureDefaultTemplates() {
        for (ZaFridaTemplate t : BuiltInTemplates.all()) {
            Path dir = templatesRoot.resolve(categoryDirName(t.getCategory()));
            Path target = dir.resolve(t.getId() + ".js");
            try {
                Files.createDirectories(dir);
                if (!Files.exists(target)) {
                    Files.writeString(target, t.getContent().stripTrailing() + System.lineSeparator(), StandardCharsets.UTF_8);
                }
            } catch (IOException ignored) {
                // ignore
            }
        }
    }

    private static @NotNull Path resolveTemplatesRoot(@NotNull Project project) {
        String basePath = project.getBasePath();
        if (basePath != null) {
            return Paths.get(basePath, "zafrida", "templates");
        }
        return Paths.get(System.getProperty("user.home"), ".zafrida-ui", "templates");
    }

    private static @NotNull String categoryDirName(@NotNull ZaFridaTemplateCategory category) {
        return category.name().toLowerCase();
    }

    private static @NotNull String stripExtension(@NotNull String name) {
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : name;
    }

    private static @NotNull String normalizeFileBaseName(@NotNull String name) {
        String trimmed = name.trim();
        if (trimmed.endsWith(".js")) {
            trimmed = stripExtension(trimmed);
        }
        String normalized = trimmed.replace(' ', '_');
        normalized = normalized.replaceAll("[^0-9a-zA-Z_\\-]", "_");
        return StringUtil.trimLeading(StringUtil.trimTrailing(normalized, '_'), '_');
    }

    private static @NotNull String prettifyTitle(@NotNull String baseName) {
        return baseName.replace('_', ' ');
    }

    private static @NotNull String readFile(@NotNull Path path) {
        try {
            return Files.readString(path, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return "";
        }
    }
}
