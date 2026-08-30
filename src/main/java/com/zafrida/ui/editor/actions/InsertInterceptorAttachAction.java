package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

public class InsertInterceptorAttachAction extends InsertFridaSnippetAction {
    private static final @NotNull String SNIPPET = String.join("\n",
            """
                    const getGlobalExport = Reflect.get(Module, "getGlobalExportByName");
                    const legacyFindExport = Reflect.get(Module, "findExportByName");
                    const openAddress = typeof getGlobalExport === "function"
                      ? getGlobalExport.call(Module, "open")
                      : legacyFindExport.call(Module, null, "open");
                    Interceptor.attach(openAddress, {
                      onEnter: function (args) {
                        console.log("open called");
                      },
                      onLeave: function (retval) {
                        console.log("open ->", retval);
                      }
                    });
                    """
    );

    public InsertInterceptorAttachAction() {
        super("Frida: Interceptor.attach", SNIPPET);
    }
}
