package com.zafrida.ui.config;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.components.*;
import com.intellij.util.xmlb.XmlSerializerUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@State(
    name = "ZaFridaGlobalSettings",
    storages = @Storage("zafrida-global.xml")
)
@Service(Service.Level.APP)
public final class ZaFridaGlobalSettings implements PersistentStateComponent<ZaFridaGlobalSettings> {

    public String fridaPath = "frida";
    public String pythonPath = "python3";
    public String fridaPsPath = "frida-ps";
    public String fridaLsDevicesPath = "frida-ls-devices";

    public String defaultRemoteHost = "127.0.0.1";
    public int defaultRemotePort = 14725;

    public int maxConsoleLines = 10000;
    public boolean autoScrollConsole = true;
    public int consoleFontSize = 12;

    public boolean autoSyncTemplates = true;
    public boolean showKeyboardHints = true;
    public boolean verboseMode = false;

    public int refreshDeviceIntervalSeconds = 5;
    public boolean autoRefreshDevices = false;

    public static ZaFridaGlobalSettings getInstance() {
        return ApplicationManager.getApplication().getService(ZaFridaGlobalSettings.class);
    }

    @Override
    public @Nullable ZaFridaGlobalSettings getState() {
        return this;
    }

    @Override
    public void loadState(@NotNull ZaFridaGlobalSettings state) {
        XmlSerializerUtil.copyBean(state, this);
    }
}