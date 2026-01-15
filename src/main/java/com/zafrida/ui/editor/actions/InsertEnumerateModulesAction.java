package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

public class InsertEnumerateModulesAction extends InsertFridaSnippetAction {
    private static final @NotNull String SNIPPET = String.join("\n",
            "Process.enumerateModules().forEach(function (m) {",
            "  console.log(m.name + \" \" + m.base);",
            "});"
    );

    public InsertEnumerateModulesAction() {
        super("Frida: enumerate modules", SNIPPET);
    }
}
