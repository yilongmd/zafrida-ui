package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

public class InsertSendLogAction extends InsertFridaSnippetAction {
    private static final @NotNull String SNIPPET = "send({ type: \"log\", payload: \"hello from frida\" });";

    public InsertSendLogAction() {
        super("Frida: send log message", SNIPPET);
    }
}
