package com.zafrida.ui.templates;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.settings.ZaFridaSettingsState;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;

public class ZaFridaTemplateService {

    private static final Logger LOG = Logger.getInstance(ZaFridaTemplateService.class);

    private static final String TEMPLATES_RESOURCE_PATH = "/templates";
    private static final String ZAFRIDA_DIR_NAME = ".zafrida";
    private static final String TEMPLATES_DIR_NAME = "templates";
    private static final String CUSTOM_DIR = "custom";
    private static final String ANDROID_DIR = "android";
    private static final String IOS_DIR = "ios";

    private final @NotNull Project project;
    private @NotNull Path userTemplatesRoot;

    private final List<ZaFridaTemplate> cachedTemplates = new ArrayList<>();
    private static final boolean FORCE_OVERWRITE_BUILTIN = true;
    private boolean initialized;

    public ZaFridaTemplateService(@NotNull Project project) {
        this.project = project;
        this.userTemplatesRoot = resolveTemplatesRoot();
        this.initialized = false;
    }

    private @NotNull Path resolveTemplatesRoot() {
        ZaFridaSettingsService settingsService = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
        ZaFridaSettingsState state = settingsService.getState();
        String mode = state.templatesRootMode;
        if (mode == null || mode.trim().isEmpty()) {
            mode = ZaFridaSettingsState.TEMPLATE_ROOT_MODE_SYSTEM;
        }
        String normalized = mode.trim();
        if (ZaFridaSettingsState.TEMPLATE_ROOT_MODE_IDE.equalsIgnoreCase(normalized)) {
            Path projectRoot = resolveProjectTemplatesRoot();
            if (projectRoot != null) {
                return projectRoot;
            }
            LOG.warn("Project base path unavailable, fallback to system templates root.");
        }
        return resolveSystemTemplatesRoot();
    }

    private @NotNull Path resolveSystemTemplatesRoot() {
        String userHome = System.getProperty("user.home");
        if (userHome == null || userHome.trim().isEmpty()) {
            return Paths.get(ZAFRIDA_DIR_NAME, TEMPLATES_DIR_NAME).toAbsolutePath();
        }
        return Paths.get(userHome, ZAFRIDA_DIR_NAME, TEMPLATES_DIR_NAME);
    }

    private @Nullable Path resolveProjectTemplatesRoot() {
        String basePath = project.getBasePath();
        if (basePath == null || basePath.trim().isEmpty()) {
            return null;
        }
        return Paths.get(basePath, ZAFRIDA_DIR_NAME, TEMPLATES_DIR_NAME);
    }

    private void ensureTemplatesRoot() {
        Path resolved = resolveTemplatesRoot();
        if (!resolved.equals(userTemplatesRoot)) {
            userTemplatesRoot = resolved;
            initialized = false;
        }
    }

    private void initializeTemplates() {
        try {
            Files.createDirectories(userTemplatesRoot.resolve(ANDROID_DIR));
            Files.createDirectories(userTemplatesRoot.resolve(IOS_DIR));
            Files.createDirectories(userTemplatesRoot.resolve(CUSTOM_DIR));

            copyBuiltInTemplates(ANDROID_DIR);
            copyBuiltInTemplates(IOS_DIR);

            LOG.info(String.format("Templates initialized at: %s", userTemplatesRoot));
        } catch (IOException e) {
            LOG.error("Failed to initialize templates", e);
        }
    }

    private void copyBuiltInTemplates(String platform) {
        String resourcePath = String.format("%s/%s", TEMPLATES_RESOURCE_PATH, platform);
        Path targetDir = userTemplatesRoot.resolve(platform);

        try {
            List<String> templateFiles = listResourceFiles(resourcePath);

            for (String fileName : templateFiles) {
                if (!fileName.endsWith(".js")) {
                    continue;
                }

                Path targetFile = targetDir.resolve(fileName);

                if (FORCE_OVERWRITE_BUILTIN || !Files.exists(targetFile)) {
                    String content = readResourceFile(String.format("%s/%s", resourcePath, fileName));
                    if (content != null) {
                        Files.writeString(targetFile, content, StandardCharsets.UTF_8);
                        String action;
                        if (FORCE_OVERWRITE_BUILTIN) {
                            action = "Overwritten";
                        } else {
                            action = "Copied";
                        }
                        LOG.info(String.format("%s template: %s to %s", action, fileName, platform));
                    }
                }
            }
        } catch (IOException e) {
            LOG.error(String.format("Failed to copy built-in templates for %s", platform), e);
        }
    }

    private List<String> listResourceFiles(String resourcePath) {
        List<String> files = new ArrayList<>();

        try {
            URL resourceUrl = getClass().getResource(resourcePath);
            if (resourceUrl == null) {
                LOG.warn(String.format("Resource path not found: %s", resourcePath));
                return files;
            }

            if (resourceUrl.getProtocol().equals("jar")) {
                String jarPath = resourceUrl.getPath().substring(5, resourceUrl.getPath().indexOf("!"));
                try (java.util.jar.JarFile jar = new java.util.jar.JarFile(java.net.URLDecoder.decode(jarPath, StandardCharsets.UTF_8))) {
                    String prefix = resourcePath;
                    if (resourcePath.startsWith("/")) {
                        prefix = resourcePath.substring(1);
                    }
                    if (!prefix.endsWith("/")) {
                        prefix = String.format("%s/", prefix);
                    }

                    String finalPrefix = prefix;
                    jar.stream()
                            .filter(entry -> !entry.isDirectory())
                            .filter(entry -> entry.getName().startsWith(finalPrefix))
                            .filter(entry -> entry.getName().endsWith(".js"))
                            .forEach(entry -> {
                                String name = entry.getName().substring(finalPrefix.length());
                                if (!name.contains("/")) {
                                    files.add(name);
                                }
                            });
                }
            } else {
                Path path = Paths.get(resourceUrl.toURI());
                try (Stream<Path> stream = Files.list(path)) {
                    stream.filter(p -> p.toString().endsWith(".js"))
                            .forEach(p -> files.add(p.getFileName().toString()));
                }
            }
        } catch (Exception e) {
            LOG.error(String.format("Failed to list resource files: %s", resourcePath), e);
        }

        return files;
    }

    @Nullable
    private String readResourceFile(String resourcePath) {
        try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
            if (is == null) {
                LOG.warn(String.format("Resource not found: %s", resourcePath));
                return null;
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            LOG.error(String.format("Failed to read resource: %s", resourcePath), e);
            return null;
        }
    }

    public synchronized void reload() {
        ensureTemplatesRoot();
        if (!initialized) {
            initializeTemplates();
            initialized = Files.isDirectory(userTemplatesRoot.resolve(ANDROID_DIR))
                    && Files.isDirectory(userTemplatesRoot.resolve(IOS_DIR))
                    && Files.isDirectory(userTemplatesRoot.resolve(CUSTOM_DIR));
        }
        cachedTemplates.clear();

        loadTemplatesFromDirectory(userTemplatesRoot.resolve(ANDROID_DIR), ZaFridaTemplateCategory.ANDROID);
        loadTemplatesFromDirectory(userTemplatesRoot.resolve(IOS_DIR), ZaFridaTemplateCategory.IOS);
        loadTemplatesFromDirectory(userTemplatesRoot.resolve(CUSTOM_DIR), ZaFridaTemplateCategory.CUSTOM);

        LOG.info(String.format("Loaded %s templates", cachedTemplates.size()));
    }

    private void loadTemplatesFromDirectory(Path dir, ZaFridaTemplateCategory category) {
        if (!Files.exists(dir)) {
            return;
        }

        try (Stream<Path> stream = Files.list(dir)) {
            stream.filter(p -> p.toString().endsWith(".js"))
                    .forEach(p -> {
                        try {
                            ZaFridaTemplate template = loadTemplateFromFile(p, category);
                            if (template != null) {
                                cachedTemplates.add(template);
                            }
                        } catch (Exception e) {
                            LOG.warn(String.format("Failed to load template: %s", p), e);
                        }
                    });
        } catch (IOException e) {
            LOG.error(String.format("Failed to list templates in: %s", dir), e);
        }
    }

    @Nullable
    private ZaFridaTemplate loadTemplateFromFile(Path file, ZaFridaTemplateCategory category) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        String fileName = file.getFileName().toString();
        String id = String.format("%s_%s", category.name().toLowerCase(), fileName.replace(".js", ""));

        String title = fileName.replace(".js", "").replace("_", " ");
        String description = "";

        String[] lines = content.split("\n", 3);
        if (lines.length > 0 && lines[0].startsWith("//")) {
            title = lines[0].substring(2).trim();
        }
        if (lines.length > 1 && lines[1].startsWith("//")) {
            description = lines[1].substring(2).trim();
        }

        return new ZaFridaTemplate(id, title, description, content, category, file);
    }

    public synchronized List<ZaFridaTemplate> all() {
        return new ArrayList<>(cachedTemplates);
    }

    public synchronized boolean addTemplate(ZaFridaTemplateCategory category, String name, String content) {
        ensureTemplatesRoot();
        if (category != ZaFridaTemplateCategory.CUSTOM) {
            LOG.warn("Can only add templates to CUSTOM category");
            return false;
        }

        String safeName = sanitizeFileName(name);
        if (safeName.isEmpty()) {
            LOG.warn("Custom template name is empty after normalization");
            return false;
        }
        String fileName = String.format("%s.js", safeName);
        Path customDirectory = userTemplatesRoot.resolve(CUSTOM_DIR);
        Path targetFile = customDirectory.resolve(fileName);

        try {
            Files.createDirectories(customDirectory);
            String finalContent = content;
            if (!content.startsWith("//")) {
                finalContent = String.format("// %s\n// Custom template\n\n%s", name, content);
            }

            Files.writeString(
                    targetFile,
                    finalContent,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE
            );
            reload();
            return true;
        } catch (FileAlreadyExistsException e) {
            LOG.warn(String.format("Custom template already exists: %s", targetFile));
            return false;
        } catch (IOException e) {
            LOG.error(String.format("Failed to add template: %s", name), e);
            return false;
        }
    }

    public synchronized boolean deleteTemplate(@NotNull ZaFridaTemplate template) {
        if (template.getCategory() != ZaFridaTemplateCategory.CUSTOM) {
            LOG.warn("Can only delete CUSTOM templates");
            return false;
        }

        Path filePath = template.getFilePath();
        if (filePath == null) {
            return false;
        }

        try {
            Files.deleteIfExists(filePath);
            reload();
            return true;
        } catch (IOException e) {
            LOG.error(String.format("Failed to delete template: %s", template.getId()), e);
            return false;
        }
    }

    public synchronized Path getUserTemplatesRoot() {
        ensureTemplatesRoot();
        return userTemplatesRoot;
    }

    public synchronized boolean isProjectTemplatesRoot() {
        ensureTemplatesRoot();
        Path projectRoot = resolveProjectTemplatesRoot();
        if (projectRoot == null) {
            return false;
        }
        return projectRoot.equals(userTemplatesRoot);
    }

    private String sanitizeFileName(String name) {
        return name.replaceAll("[^a-zA-Z0-9_\\-]", "_").toLowerCase();
    }
}
