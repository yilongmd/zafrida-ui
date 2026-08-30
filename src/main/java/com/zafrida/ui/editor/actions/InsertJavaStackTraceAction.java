package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

public class InsertJavaStackTraceAction extends InsertFridaSnippetAction {
    private static final @NotNull String SNIPPET = """
            console.log(Java.use('android.util.Log')
                    .getStackTraceString(Java.use('java.lang.Throwable')
                            .$new()));
            """;

    public InsertJavaStackTraceAction() {
        super("Frida: print Java stack trace", SNIPPET);
    }
}
