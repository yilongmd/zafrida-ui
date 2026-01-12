package com.zafrida.ui.templates;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.file.Path;

public final class ZaFridaTemplate {

    private final @NotNull String id;
    private final @NotNull String title;
    private final @NotNull String description;
    private final @NotNull ZaFridaTemplateCategory category;
    private final @NotNull String content;
    private final @Nullable Path sourcePath;

    public ZaFridaTemplate(@NotNull String id,
                           @NotNull String title,
                           @NotNull String description,
                           @NotNull ZaFridaTemplateCategory category,
                           @NotNull String content) {
        this(id, title, description, category, content, null);
    }

    public ZaFridaTemplate(@NotNull String id,
                           @NotNull String title,
                           @NotNull String description,
                           @NotNull ZaFridaTemplateCategory category,
                           @NotNull String content,
                           @Nullable Path sourcePath) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.category = category;
        this.content = content;
        this.sourcePath = sourcePath;
    }

    public @NotNull String getId() {
        return id;
    }

    public @NotNull String getTitle() {
        return title;
    }

    public @NotNull String getDescription() {
        return description;
    }

    public @NotNull ZaFridaTemplateCategory getCategory() {
        return category;
    }

    public @NotNull String getContent() {
        return content;
    }

    public @Nullable Path getSourcePath() {
        return sourcePath;
    }
}
