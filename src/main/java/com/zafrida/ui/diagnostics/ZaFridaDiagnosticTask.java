package com.zafrida.ui.diagnostics;

import org.jetbrains.annotations.NotNull;

public interface ZaFridaDiagnosticTask {

    @NotNull ZaFridaDiagnosticResult run(@NotNull ZaFridaDiagnosticsContext context) throws Exception;
}
