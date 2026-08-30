package com.zafrida.ui.diagnostics;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public final class ZaFridaDiagnosticResult {

    private final @NotNull ZaFridaDiagnosticStatus status;
    private final @Nullable String message;
    private final @Nullable String tip;

    private ZaFridaDiagnosticResult(@NotNull ZaFridaDiagnosticStatus status,
                                    @Nullable String message,
                                    @Nullable String tip) {
        this.status = status;
        this.message = message;
        this.tip = tip;
    }

    public static @NotNull ZaFridaDiagnosticResult success(@Nullable String message) {
        return new ZaFridaDiagnosticResult(ZaFridaDiagnosticStatus.SUCCESS, message, null);
    }

    public static @NotNull ZaFridaDiagnosticResult failed(@Nullable String message, @Nullable String tip) {
        return new ZaFridaDiagnosticResult(ZaFridaDiagnosticStatus.FAILED, message, tip);
    }

    public static @NotNull ZaFridaDiagnosticResult skipped(@Nullable String message, @Nullable String tip) {
        return new ZaFridaDiagnosticResult(ZaFridaDiagnosticStatus.SKIPPED, message, tip);
    }

    public static @NotNull ZaFridaDiagnosticResult timeout(@Nullable String message, @Nullable String tip) {
        return new ZaFridaDiagnosticResult(ZaFridaDiagnosticStatus.FAILED, message, tip);
    }

    public @NotNull ZaFridaDiagnosticStatus getStatus() {
        return status;
    }

    public @Nullable String getMessage() {
        return message;
    }

    public @Nullable String getTip() {
        return tip;
    }
}
