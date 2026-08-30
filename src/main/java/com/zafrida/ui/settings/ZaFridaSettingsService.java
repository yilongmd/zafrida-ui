package com.zafrida.ui.settings;

import com.intellij.openapi.components.PersistentStateComponent;
import com.intellij.openapi.components.State;
import com.intellij.openapi.components.Storage;
import com.intellij.util.xmlb.XmlSerializerUtil;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;

@State(
        name = "ZaFridaSettings",
        storages = {@Storage("zafrida.xml")}
)
public final class ZaFridaSettingsService implements PersistentStateComponent<ZaFridaSettingsState> {

    public static final String DEFAULT_FRIDA_VERSION = "16";
    private static final String FRIDA_17_VERSION = "17";

    private final ZaFridaSettingsState state = new ZaFridaSettingsState();

    @Override
    public @NotNull ZaFridaSettingsState getState() {
        return state;
    }

    @Override
    public void loadState(@NotNull ZaFridaSettingsState loaded) {
        XmlSerializerUtil.copyBean(loaded, state);
        normalizeState();
    }

    private void normalizeState() {
        if (ZaStrUtil.isBlank(state.fridaExecutable)) {
            state.fridaExecutable = "frida";
        }
        if (ZaStrUtil.isBlank(state.fridaPsExecutable)) {
            state.fridaPsExecutable = "frida-ps";
        }
        if (ZaStrUtil.isBlank(state.fridaLsDevicesExecutable)) {
            state.fridaLsDevicesExecutable = "frida-ls-devices";
        }
        if (ZaStrUtil.isBlank(state.fridaVersion)) {
            state.fridaVersion = DEFAULT_FRIDA_VERSION;
        }
        if (state.vscodeExecutable == null) {
            state.vscodeExecutable = "";
        }
        if (state.editor010Executable == null) {
            state.editor010Executable = "";
        }
        if (ZaStrUtil.isBlank(state.logsDirName)) {
            state.logsDirName = "zafrida-logs";
        }
        if (ZaStrUtil.isBlank(state.defaultRemoteHost)) {
            state.defaultRemoteHost = "127.0.0.1";
        }
        if (state.defaultRemotePort <= 0 || state.defaultRemotePort > 65_535) {
            state.defaultRemotePort = 14725;
        }
        if (!ZaFridaSettingsState.TEMPLATE_ROOT_MODE_SYSTEM.equalsIgnoreCase(state.templatesRootMode)
                && !ZaFridaSettingsState.TEMPLATE_ROOT_MODE_IDE.equalsIgnoreCase(state.templatesRootMode)) {
            state.templatesRootMode = ZaFridaSettingsState.TEMPLATE_ROOT_MODE_SYSTEM;
        }
        if (state.skillsApiPort <= 0 || state.skillsApiPort > 65_535) {
            state.skillsApiPort = ZaFridaSettingsState.DEFAULT_SKILLS_API_PORT;
        }
        List<String> normalizedHosts = new ArrayList<>();
        if (state.remoteHosts != null) {
            for (String host : state.remoteHosts) {
                if (ZaStrUtil.isBlank(host)) {
                    continue;
                }
                String normalizedHost = host.trim();
                if (!normalizedHosts.contains(normalizedHost)) {
                    normalizedHosts.add(normalizedHost);
                }
            }
        }
        state.remoteHosts = normalizedHosts;
    }

    public @NotNull List<String> getRemoteHosts() {
        if (state.remoteHosts == null) {
            return List.of();
        }
        return new ArrayList<>(state.remoteHosts);
    }

    public void addRemoteHost(@NotNull String host) {
        String h = host.trim();
        if (h.isEmpty()) {
            return;
        }
        if (state.remoteHosts == null) {
            state.remoteHosts = new ArrayList<>();
        }
        if (!state.remoteHosts.contains(h)) {
            state.remoteHosts.add(h);
        }
    }

    public void removeRemoteHost(@NotNull String host) {
        if (state.remoteHosts == null) {
            return;
        }
        state.remoteHosts.remove(host.trim());
    }

    public @Nullable String getFridaExecutable() {
        return state.fridaExecutable;
    }

    public @NotNull String getFridaVersion() {
        if (ZaStrUtil.isBlank(state.fridaVersion)) {
            return DEFAULT_FRIDA_VERSION;
        }
        return state.fridaVersion.trim();
    }

    public boolean isFrida17OrLater() {
        return ZaStrUtil.compareVersion(getFridaVersion(), FRIDA_17_VERSION) >= 0;
    }
}
