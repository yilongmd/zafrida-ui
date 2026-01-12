package com.zafrida.ui.templates;

import org.jetbrains.annotations.NotNull;

import java.nio.file.Path;

public final class ZaFridaTemplateFile {

    private final @NotNull ZaFridaTemplate template;
    private final @NotNull Path path;

    public ZaFridaTemplateFile(@NotNull ZaFridaTemplate template, @NotNull Path path) {
        this.template = template;
        this.path = path;
    }

    public @NotNull ZaFridaTemplate getTemplate() {
        return template;
    }

    public @NotNull Path getPath() {
        return path;
    }
}
