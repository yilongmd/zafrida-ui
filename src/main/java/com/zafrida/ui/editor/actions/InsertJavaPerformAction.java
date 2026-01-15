package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

public class InsertJavaPerformAction extends InsertFridaSnippetAction {
    private static final @NotNull String SNIPPET = String.join("\n",
            "Java.perform(function () {",
            "  var Activity = Java.use(\"android.app.Activity\");",
            "  console.log(Activity);",
            "});"
    );

    public InsertJavaPerformAction() {
        super("Frida: Java.perform block", SNIPPET);
    }
}
