package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

public class InsertThreadCurrentContextAction extends InsertFridaSnippetAction {
    private static final @NotNull String SNIPPET = """
            Thread.currentContext();
            """;

    public InsertThreadCurrentContextAction() {
        super("Frida: Thread.currentContext", SNIPPET);
    }
}
