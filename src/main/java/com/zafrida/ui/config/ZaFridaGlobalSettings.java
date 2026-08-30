package com.zafrida.ui.config;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.components.PersistentStateComponent;
import com.intellij.openapi.components.RoamingType;
import com.intellij.openapi.components.Service;
import com.intellij.openapi.components.State;
import com.intellij.openapi.components.Storage;
import com.intellij.util.xmlb.XmlSerializerUtil;
import org.jetbrains.annotations.NotNull;

@State(
    name = "ZaFridaGlobalSettings",
    storages = @Storage(value = "zafrida-global.xml", roamingType = RoamingType.DISABLED)
)
@Service(Service.Level.APP)
public final class ZaFridaGlobalSettings implements PersistentStateComponent<ZaFridaGlobalSettings> {

    public boolean environmentDoctorShown = false;

    public static ZaFridaGlobalSettings getInstance() {
        return ApplicationManager.getApplication().getService(ZaFridaGlobalSettings.class);
    }

    @Override
    public @NotNull ZaFridaGlobalSettings getState() {
        return this;
    }

    @Override
    public void loadState(@NotNull ZaFridaGlobalSettings state) {
        XmlSerializerUtil.copyBean(state, this);
    }
}
