package com.zafrida.ui.fridaproject;

import org.jetbrains.annotations.Nullable;

public interface ZaFridaProjectListener {
    void onActiveProjectChanged(@Nullable ZaFridaFridaProject newProject);
}
