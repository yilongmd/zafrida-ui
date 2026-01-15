package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

public class InsertInterceptorAttachAction extends InsertFridaSnippetAction {
    private static final @NotNull String SNIPPET = String.join("\n",
            "Interceptor.attach(Module.findExportByName(null, \"open\"), {",
            "  onEnter: function (args) {",
            "    console.log(\"open called\");",
            "  },",
            "  onLeave: function (retval) {",
            "    console.log(\"open ->\", retval);",
            "  }",
            "});"
    );

    public InsertInterceptorAttachAction() {
        super("Frida: Interceptor.attach", SNIPPET);
    }
}
