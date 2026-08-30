package com.zafrida.ui.diagnostics;

import com.intellij.openapi.project.Project;
import com.zafrida.ui.frida.FridaDevice;
import com.zafrida.ui.python.PythonEnvInfo;
import com.zafrida.ui.settings.ZaFridaSettingsState;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public final class ZaFridaDiagnosticsContext {

    private final @NotNull Project project;
    private final @Nullable FridaDevice device;
    private final @NotNull ZaFridaSettingsState settings;
    private final @Nullable PythonEnvInfo pythonEnv;
    private final @Nullable String pythonEnvError;

    public ZaFridaDiagnosticsContext(@NotNull Project project,
                                     @Nullable FridaDevice device,
                                     @NotNull ZaFridaSettingsState settings,
                                     @Nullable PythonEnvInfo pythonEnv,
                                     @Nullable String pythonEnvError) {
        this.project = project;
        this.device = device;
        this.settings = settings;
        this.pythonEnv = pythonEnv;
        this.pythonEnvError = pythonEnvError;
    }

    public @NotNull Project getProject() {
        return project;
    }

    public @Nullable FridaDevice getDevice() {
        return device;
    }

    public @NotNull ZaFridaSettingsState getSettings() {
        return settings;
    }

    public @Nullable PythonEnvInfo getPythonEnv() {
        return pythonEnv;
    }

    public @Nullable String getPythonEnvError() {
        return pythonEnvError;
    }
}
