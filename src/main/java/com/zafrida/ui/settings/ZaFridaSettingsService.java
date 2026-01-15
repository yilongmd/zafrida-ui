package com.zafrida.ui.settings;

import com.intellij.openapi.components.PersistentStateComponent;
import com.intellij.openapi.components.State;
import com.intellij.openapi.components.Storage;
import com.intellij.util.xmlb.XmlSerializerUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;
/**
 * [服务层] 全局配置持久化服务。
 * <p>
 * <strong>架构角色：</strong>
 * 插件级单例服务，负责管理 {@link ZaFridaSettingsState} 的生命周期。
 * 任何需要读取 {@code frida} 路径或全局 {@code remoteHosts} 列表的组件，
 * 都应通过 {@code ApplicationManager.getApplication().getService(ZaFridaSettingsService.class)} 获取此服务。
 */
@State(
        name = "ZaFridaSettings",
        storages = {@Storage("zafrida.xml")}
)
public final class ZaFridaSettingsService implements PersistentStateComponent<ZaFridaSettingsState> {

    private final ZaFridaSettingsState state = new ZaFridaSettingsState();

    @Override
    public @NotNull ZaFridaSettingsState getState() {
        return state;
    }

    @Override
    public void loadState(@NotNull ZaFridaSettingsState loaded) {
        XmlSerializerUtil.copyBean(loaded, state);
    }

    public @NotNull List<String> getRemoteHosts() {
        if (state.remoteHosts == null) return List.of();
        return new ArrayList<>(state.remoteHosts);
    }

    public void addRemoteHost(@NotNull String host) {
        String h = host.trim();
        if (h.isEmpty()) return;
        if (state.remoteHosts == null) state.remoteHosts = new ArrayList<>();
        if (!state.remoteHosts.contains(h)) {
            state.remoteHosts.add(h);
        }
    }

    public void removeRemoteHost(@NotNull String host) {
        if (state.remoteHosts == null) return;
        state.remoteHosts.remove(host.trim());
    }

    public @Nullable String getFridaExecutable() {
        return state.fridaExecutable;
    }
}
