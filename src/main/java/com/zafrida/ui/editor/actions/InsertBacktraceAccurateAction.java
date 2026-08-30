package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

public class InsertBacktraceAccurateAction extends InsertFridaSnippetAction {
    private static final @NotNull String SNIPPET = """
            console.log('backtrace called from:\\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n') + '\\n');
            """;

    public InsertBacktraceAccurateAction() {
        super("Frida: backtrace (ACCURATE)", SNIPPET);
    }
}
