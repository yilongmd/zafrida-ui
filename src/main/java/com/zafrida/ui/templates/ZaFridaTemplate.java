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

    /** 模板唯一标识 */
    private final @NotNull String id;
    /** 模板标题 */
    private final @NotNull String title;
    /** 模板描述 */
    private final @Nullable String description;
    /** 模板内容 */
    private final @NotNull String content;
    /** 模板分类 */
    private final @NotNull ZaFridaTemplateCategory category;
    /** 模板文件路径（自定义模板） */
    private final @Nullable Path filePath;

    /**
     * 构造函数。
     * @param id 模板标识
     * @param title 模板标题
     * @param description 模板描述
     * @param content 模板内容
     * @param category 模板分类
     * @param filePath 文件路径（可为空）
     */
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

    /**
     * 获取模板 ID。
     * @return 模板 ID
     */
    public @NotNull String getId() {
        return id;
    }

    /**
     * 获取模板标题。
     * @return 模板标题
     */
    public @NotNull String getTitle() {
        return title;
    }

    /**
     * 获取模板描述。
     * @return 模板描述或 null
     */
    public @Nullable String getDescription() {
        return description;
    }

    /**
     * 获取模板内容。
     * @return 模板内容
     */
    public @NotNull String getContent() {
        return content;
    }

    /**
     * 获取模板分类。
     * @return 模板分类
     */
    public @NotNull ZaFridaTemplateCategory getCategory() {
        return category;
    }

    /**
     * 获取模板文件路径。
     * @return 文件路径或 null
     */
    public @Nullable Path getFilePath() {
        return filePath;
    }

    /**
     * 是否为自定义模板。
     * @return true 表示自定义
     */
    public boolean isCustom() {
        return category == ZaFridaTemplateCategory.CUSTOM;
    }

    /**
     * 是否可编辑（有文件路径）。
     * @return true 表示可编辑
     */
    public boolean isEditable() {
        return filePath != null;
    }

    /**
     * 比较模板相等性（基于 ID）。
     * @param o 比较对象
     * @return true 表示相等
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ZaFridaTemplate that = (ZaFridaTemplate) o;
        return Objects.equals(id, that.id);
    }

    /**
     * 计算哈希值（基于 ID）。
     * @return 哈希值
     */
    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    /**
     * 返回模板显示名称。
     * @return 标题
     */
    @Override
    public String toString() {
        return title;
    }
}
