package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

public class InsertJavaPerformAction extends InsertFridaSnippetAction {
    private static final @NotNull String SNIPPET = String.join("\n",
            """
                    Java.perform(function () {

                    });
                    """
    );

    public InsertJavaPerformAction() {
        super("Frida: Java.perform block", SNIPPET);
    }
}
