package com.zafrida.ui.diagnostics;

import org.jetbrains.annotations.NotNull;

import java.util.List;

public interface ZaFridaDiagnosticsListener {

    void onItemUpdated(@NotNull ZaFridaDiagnosticItem item);

    void onAllCompleted(@NotNull List<ZaFridaDiagnosticItem> items);
}
