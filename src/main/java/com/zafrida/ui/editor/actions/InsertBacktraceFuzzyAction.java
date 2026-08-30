package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

public class InsertBacktraceFuzzyAction extends InsertFridaSnippetAction {
    private static final @NotNull String SNIPPET = """
            console.log('backtrace called from:\\n' + Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\\n') + '\\n');
            """;

    public InsertBacktraceFuzzyAction() {
        super("Frida: backtrace (FUZZY)", SNIPPET);
    }
}
