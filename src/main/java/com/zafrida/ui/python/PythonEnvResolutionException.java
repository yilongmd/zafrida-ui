package com.zafrida.ui.python;

import org.jetbrains.annotations.NotNull;

public final class PythonEnvResolutionException extends IllegalArgumentException {

    public PythonEnvResolutionException(@NotNull String message) {
        super(message);
    }

    public PythonEnvResolutionException(@NotNull String message, @NotNull Throwable cause) {
        super(message, cause);
    }
}
