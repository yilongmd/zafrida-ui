package com.zafrida.ui.config;

import com.intellij.openapi.components.*;
import com.intellij.openapi.project.Project;
import com.intellij.util.xmlb.XmlSerializerUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;

@State(
    name = "ZaFridaProjectSettings",
    storages = @Storage("zafrida-project.xml")
)
@Service(Service.Level.PROJECT)
public final class ZaFridaProjectSettings implements PersistentStateComponent<ZaFridaProjectSettings> {

    public String packageName = "";
    public List<String> recentPackages = new ArrayList<>();

    public String lastSelectedDevice = "";
    public DeviceConnectionMode connectionMode = DeviceConnectionMode.USB;

    public String remoteHost = "127.0.0.1";
    public int remotePort = 14725;

    public String additionalArgs = "";
    public boolean spawnMode = true;

    public static ZaFridaProjectSettings getInstance(@NotNull Project project) {
        return project.getService(ZaFridaProjectSettings.class);
    }

    @Override
    public @Nullable ZaFridaProjectSettings getState() {
        return this;
    }

    @Override
    public void loadState(@NotNull ZaFridaProjectSettings state) {
        XmlSerializerUtil.copyBean(state, this);
    }

    public void addRecentPackage(String pkg) {
        if (pkg == null || pkg.trim().isEmpty()) return;
        pkg = pkg.trim();
        recentPackages.remove(pkg);
        recentPackages.add(0, pkg);
        if (recentPackages.size() > 20) {
            recentPackages = new ArrayList<>(recentPackages.subList(0, 20));
        }
    }

    public enum DeviceConnectionMode {
        USB("USB", "-U"),
        REMOTE("Remote", "-H"),
        GADGET("Gadget", "-H");

        private final String displayName;
        private final String fridaFlag;

        DeviceConnectionMode(String displayName, String fridaFlag) {
            this.displayName = displayName;
            this.fridaFlag = fridaFlag;
        }

        public String getDisplayName() {
            return displayName;
        }

        public String getFridaFlag() {
            return fridaFlag;
        }

        @Override
        public String toString() {
            return displayName;
        }
    }
}