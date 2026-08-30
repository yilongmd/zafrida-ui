package com.zafrida.ui.diagnostics;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.concurrent.atomic.AtomicBoolean;

public final class ZaFridaDiagnosticItem {

    private final @NotNull String id;
    private final @NotNull String title;
    private final @NotNull String description;
    private final int timeoutMs;
    private final @NotNull ZaFridaDiagnosticTask task;

    private final AtomicBoolean skipRequested = new AtomicBoolean(false);

    private volatile @NotNull ZaFridaDiagnosticStatus status = ZaFridaDiagnosticStatus.PENDING;
    private volatile @Nullable String message;
    private volatile @Nullable String tip;

    public ZaFridaDiagnosticItem(@NotNull String id,
                                 @NotNull String title,
                                 @NotNull String description,
                                 int timeoutMs,
                                 @NotNull ZaFridaDiagnosticTask task) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.timeoutMs = timeoutMs;
        this.task = task;
    }

    public @NotNull String getId() {
        return id;
    }

    public @NotNull String getTitle() {
        return title;
    }

    public @NotNull String getDescription() {
        return description;
    }

    public int getTimeoutMs() {
        return timeoutMs;
    }

    public @NotNull ZaFridaDiagnosticTask getTask() {
        return task;
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

    public void updateStatus(@NotNull ZaFridaDiagnosticStatus status,
                             @Nullable String message,
                             @Nullable String tip) {
        this.status = status;
        this.message = message;
        this.tip = tip;
    }

    public void requestSkip() {
        skipRequested.set(true);
    }

    public boolean isSkipRequested() {
        return skipRequested.get();
    }

    public void reset() {
        skipRequested.set(false);
        updateStatus(ZaFridaDiagnosticStatus.PENDING, null, null);
    }
}
