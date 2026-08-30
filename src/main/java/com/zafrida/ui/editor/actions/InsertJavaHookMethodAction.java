package com.zafrida.ui.editor.actions;

import org.jetbrains.annotations.NotNull;

public class InsertJavaHookMethodAction extends InsertFridaSnippetAction {
    private static final @NotNull String SNIPPET = String.join("\n",
            """
                    Java.perform(function () {
                      var clazz = Java.use("com.example.ClassName");
                      clazz.method.overload("java.lang.String").implementation = function (arg) {
                        console.log("method called:", arg);
                        return this.method(arg);
                      };
                    });
                    """
    );

    public InsertJavaHookMethodAction() {
        super("Frida: hook Java method", SNIPPET);
    }
}
