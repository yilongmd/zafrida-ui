package com.zafrida.ui.templates;

import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.io.FileUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
/**
 * [核心服务] 模板文件系统管理器。
 * <p>
 * <strong>职责：</strong>
 * 1. <strong>初始化：</strong> 首次启动时将内置资源 (Resources) 中的模板释放到用户目录 {@code ~/.zafrida/templates}。
 * 2. <strong>CRUD：</strong> 提供对 {@code custom/} 目录下自定义模板的增删改查 API。
 * 3. <strong>加载：</strong> 扫描磁盘文件并构建内存中的 {@link ZaFridaTemplate} 列表供 UI 展示。
 */
public class ZaFridaTemplateService {

    private static final Logger LOG = Logger.getInstance(ZaFridaTemplateService.class);

    private static final String TEMPLATES_RESOURCE_PATH = "/templates";
    private static final String USER_TEMPLATES_DIR = "zafrida/templates";
    private static final String CUSTOM_DIR = "custom";
    private static final String ANDROID_DIR = "android";
    private static final String IOS_DIR = "ios";

    private final @NotNull Project project;
    private final @NotNull Path userTemplatesRoot;

    private final List<ZaFridaTemplate> cachedTemplates = new ArrayList<>();

    public ZaFridaTemplateService(@NotNull Project project) {
        this.project = project;

        // 用户模板目录：~/.zafrida/templates 或 IDE配置目录
        String userHome = System.getProperty("user.home");
        this.userTemplatesRoot = Paths.get(userHome, ".zafrida", "templates");

        initializeTemplates();
        reload();
    }

    /**
     * 初始化模板目录，将内置模板复制到用户目录
     */
    private void initializeTemplates() {
        try {
            // 创建目录结构
            Files.createDirectories(userTemplatesRoot.resolve(ANDROID_DIR));
            Files.createDirectories(userTemplatesRoot.resolve(IOS_DIR));
            Files.createDirectories(userTemplatesRoot.resolve(CUSTOM_DIR));

            // 复制内置模板
            copyBuiltInTemplates(ANDROID_DIR);
            copyBuiltInTemplates(IOS_DIR);

            LOG.info("Templates initialized at: " + userTemplatesRoot);
        } catch (IOException e) {
            LOG.error("Failed to initialize templates", e);
        }
    }

    /**
     * 复制内置模板到用户目录（不覆盖已存在的文件）
     */
    private void copyBuiltInTemplates(String platform) {
        String resourcePath = TEMPLATES_RESOURCE_PATH + "/" + platform;
        Path targetDir = userTemplatesRoot.resolve(platform);

        try {
            // 获取资源目录中的模板列表
            List<String> templateFiles = listResourceFiles(resourcePath);

            for (String fileName : templateFiles) {
                if (!fileName.endsWith(".js")) continue;

                Path targetFile = targetDir.resolve(fileName);

                // 只在文件不存在时复制
                if (!Files.exists(targetFile)) {
                    String content = readResourceFile(resourcePath + "/" + fileName);
                    if (content != null) {
                        Files.writeString(targetFile, content, StandardCharsets.UTF_8);
                        LOG.info("Copied template: " + fileName + " to " + platform);
                    }
                }
            }
        } catch (IOException e) {
            LOG.error("Failed to copy built-in templates for " + platform, e);
        }
    }

    /**
     * 列出资源目录中的文件
     */
    private List<String> listResourceFiles(String resourcePath) {
        List<String> files = new ArrayList<>();

        // 硬编码内置模板文件名（因为无法直接列出资源目录）
        if (resourcePath.endsWith("/" + ANDROID_DIR)) {
            files.addAll(Arrays.asList(
                    "hook_java_method.js",
                    "hook_constructor.js",
                    "enum_classes.js",
                    "hook_native.js",
                    "ssl_pinning_bypass.js"
            ));
        } else if (resourcePath.endsWith("/" + IOS_DIR)) {
            files.addAll(Arrays.asList(
                    "hook_objc_method.js",
                    "list_classes.js",
                    "list_methods.js",
                    "ssl_pinning_bypass.js"
            ));
        }

        return files;
    }

    /**
     * 读取资源文件内容
     */
    @Nullable
    private String readResourceFile(String resourcePath) {
        try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
            if (is == null) {
                LOG.warn("Resource not found: " + resourcePath);
                return null;
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            LOG.error("Failed to read resource: " + resourcePath, e);
            return null;
        }
    }

    /**
     * 重新加载所有模板
     */
    public void reload() {
        cachedTemplates.clear();

        // 加载 Android 模板
        loadTemplatesFromDirectory(userTemplatesRoot.resolve(ANDROID_DIR), ZaFridaTemplateCategory.ANDROID);

        // 加载 iOS 模板
        loadTemplatesFromDirectory(userTemplatesRoot.resolve(IOS_DIR), ZaFridaTemplateCategory.IOS);

        // 加载自定义模板
        loadTemplatesFromDirectory(userTemplatesRoot.resolve(CUSTOM_DIR), ZaFridaTemplateCategory.CUSTOM);

        LOG.info("Loaded " + cachedTemplates.size() + " templates");
    }

    /**
     * 从目录加载模板
     */
    private void loadTemplatesFromDirectory(Path dir, ZaFridaTemplateCategory category) {
        if (!Files.exists(dir)) return;

        try (Stream<Path> stream = Files.list(dir)) {
            stream.filter(p -> p.toString().endsWith(".js"))
                    .forEach(p -> {
                        try {
                            ZaFridaTemplate template = loadTemplateFromFile(p, category);
                            if (template != null) {
                                cachedTemplates.add(template);
                            }
                        } catch (Exception e) {
                            LOG.warn("Failed to load template: " + p, e);
                        }
                    });
        } catch (IOException e) {
            LOG.error("Failed to list templates in: " + dir, e);
        }
    }

    /**
     * 从文件加载模板
     */
    @Nullable
    private ZaFridaTemplate loadTemplateFromFile(Path file, ZaFridaTemplateCategory category) throws IOException {
        String content = Files.readString(file, StandardCharsets.UTF_8);
        String fileName = file.getFileName().toString();
        String id = category.name().toLowerCase() + "_" + fileName.replace(".js", "");

        // 解析标题和描述（从文件前两行注释中提取）
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

    /**
     * 获取所有模板
     */
    public List<ZaFridaTemplate> all() {
        return new ArrayList<>(cachedTemplates);
    }

    /**
     * 按分类获取模板
     */
    public List<ZaFridaTemplate> byCategory(ZaFridaTemplateCategory category) {
        return cachedTemplates.stream()
                .filter(t -> t.getCategory() == category)
                .collect(Collectors.toList());
    }

    /**
     * 添加自定义模板
     */
    public boolean addTemplate(ZaFridaTemplateCategory category, String name, String content) {
        if (category != ZaFridaTemplateCategory.CUSTOM) {
            LOG.warn("Can only add templates to CUSTOM category");
            return false;
        }

        String fileName = sanitizeFileName(name) + ".js";
        Path targetFile = userTemplatesRoot.resolve(CUSTOM_DIR).resolve(fileName);

        try {
            // 确保内容以标题注释开头
            String finalContent = content;
            if (!content.startsWith("//")) {
                finalContent = "// " + name + "\n// Custom template\n\n" + content;
            }

            Files.writeString(targetFile, finalContent, StandardCharsets.UTF_8);
            reload();
            return true;
        } catch (IOException e) {
            LOG.error("Failed to add template: " + name, e);
            return false;
        }
    }

    /**
     * 更新模板内容
     */
    public boolean updateTemplate(@NotNull ZaFridaTemplate template, String newContent) {
        Path filePath = template.getFilePath();
        if (filePath == null || !Files.exists(filePath)) {
            LOG.warn("Template file not found: " + template.getId());
            return false;
        }

        try {
            Files.writeString(filePath, newContent, StandardCharsets.UTF_8);
            reload();
            return true;
        } catch (IOException e) {
            LOG.error("Failed to update template: " + template.getId(), e);
            return false;
        }
    }

    /**
     * 删除模板
     */
    public boolean deleteTemplate(@NotNull ZaFridaTemplate template) {
        // 只允许删除自定义模板
        if (template.getCategory() != ZaFridaTemplateCategory.CUSTOM) {
            LOG.warn("Can only delete CUSTOM templates");
            return false;
        }

        Path filePath = template.getFilePath();
        if (filePath == null) return false;

        try {
            Files.deleteIfExists(filePath);
            reload();
            return true;
        } catch (IOException e) {
            LOG.error("Failed to delete template: " + template.getId(), e);
            return false;
        }
    }

    /**
     * 获取用户模板目录路径
     */
    public Path getUserTemplatesRoot() {
        return userTemplatesRoot;
    }

    /**
     * 清理文件名
     */
    private String sanitizeFileName(String name) {
        return name.replaceAll("[^a-zA-Z0-9_\\-]", "_").toLowerCase();
    }
}