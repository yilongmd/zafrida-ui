package com.zafrida.ui.templates;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.file.Path;
import java.util.Objects;
/**
 * [DTO] Frida 脚本模板实体。
 * <p>
 * <strong>数据流：</strong>
 * 代表一个可复用的代码片段（Snippet）。
 * <ul>
 * <li>{@code id}: 唯一标识符，用于生成 {@code //== ZAFrida:TEMPLATE:id:BEGIN ==} 标记。</li>
 * <li>{@code content}: 实际的 JavaScript 代码内容。</li>
 * <li>{@code filePath}: 如果是用户自定义模板，指向磁盘上的物理文件；内置模板此字段可能为空。</li>
 * </ul>
 */
public class ZaFridaTemplate {

    private final @NotNull String id;
    private final @NotNull String title;
    private final @Nullable String description;
    private final @NotNull String content;
    private final @NotNull ZaFridaTemplateCategory category;
    private final @Nullable Path filePath;

    public ZaFridaTemplate(@NotNull String id,
                           @NotNull String title,
                           @Nullable String description,
                           @NotNull String content,
                           @NotNull ZaFridaTemplateCategory category,
                           @Nullable Path filePath) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.content = content;
        this.category = category;
        this.filePath = filePath;
    }

    public @NotNull String getId() {
        return id;
    }

    public @NotNull String getTitle() {
        return title;
    }

    public @Nullable String getDescription() {
        return description;
    }

    public @NotNull String getContent() {
        return content;
    }

    public @NotNull ZaFridaTemplateCategory getCategory() {
        return category;
    }

    public @Nullable Path getFilePath() {
        return filePath;
    }

    public boolean isCustom() {
        return category == ZaFridaTemplateCategory.CUSTOM;
    }

    public boolean isEditable() {
        return filePath != null;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ZaFridaTemplate that = (ZaFridaTemplate) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return title;
    }
}