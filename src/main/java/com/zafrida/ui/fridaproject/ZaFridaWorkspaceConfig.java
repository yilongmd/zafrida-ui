package com.zafrida.ui.fridaproject;

import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;

public final class ZaFridaWorkspaceConfig {
    public static final int VERSION = 1;
    public @Nullable String lastSelected = null;
    public final List<ZaFridaFridaProject> projects = new ArrayList<>();
}
