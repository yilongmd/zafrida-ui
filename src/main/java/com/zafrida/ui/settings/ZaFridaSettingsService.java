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

    /** 持久化状态对象 */
    private final ZaFridaSettingsState state = new ZaFridaSettingsState();

    /**
     * 获取持久化状态。
     * @return 配置状态
     */
    @Override
    public @NotNull ZaFridaSettingsState getState() {
        return state;
    }

    /**
     * 加载持久化状态。
     * @param loaded 已加载的状态
     */
    @Override
    public void loadState(@NotNull ZaFridaSettingsState loaded) {
        XmlSerializerUtil.copyBean(loaded, state);
    }

    /**
     * 获取远程主机列表副本。
     * @return 远程主机列表
     */
    public @NotNull List<String> getRemoteHosts() {
        if (state.remoteHosts == null) return List.of();
        return new ArrayList<>(state.remoteHosts);
    }

    /**
     * 添加远程主机地址。
     * @param host 主机地址
     */
    public void addRemoteHost(@NotNull String host) {
        String h = host.trim();
        if (h.isEmpty()) return;
        if (state.remoteHosts == null) state.remoteHosts = new ArrayList<>();
        if (!state.remoteHosts.contains(h)) {
            state.remoteHosts.add(h);
        }
    }

    /**
     * 移除远程主机地址。
     * @param host 主机地址
     */
    public void removeRemoteHost(@NotNull String host) {
        if (state.remoteHosts == null) return;
        state.remoteHosts.remove(host.trim());
    }

    /**
     * 获取 frida 可执行文件路径。
     * @return 路径或 null
     */
    public @Nullable String getFridaExecutable() {
        return state.fridaExecutable;
    }
}
