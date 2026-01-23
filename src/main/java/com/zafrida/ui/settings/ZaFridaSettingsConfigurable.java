package com.zafrida.ui.settings;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.options.SearchableConfigurable;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JComponent;
/**
 * [UI入口] IDE "Settings/Preferences" 菜单集成。
 * <p>
 * <strong>功能：</strong>
 * 将 {@link ZaFridaSettingsComponent} (UI 面板) 注册到 IntelliJ 的设置树中。
 * 负责在 UI 和 {@link ZaFridaSettingsService} (持久化状态) 之间同步数据（Apply/Reset 逻辑）。
 */
public final class ZaFridaSettingsConfigurable implements SearchableConfigurable {

    /** 全局设置服务 */
    private final ZaFridaSettingsService settingsService;
    /** UI 组件实例 */
    private @Nullable ZaFridaSettingsComponent component;

    /**
     * 构造函数。
     */
    public ZaFridaSettingsConfigurable() {
        this.settingsService = ApplicationManager.getApplication().getService(ZaFridaSettingsService.class);
    }

    /**
     * 配置项 ID。
     * @return 配置 ID
     */
    @Override
    public @NotNull String getId() {
        return "com.zafrida.ui.settings";
    }

    /**
     * 配置项显示名称。
     * @return 显示名称
     */
    @Override
    public String getDisplayName() {
        return "ZAFrida";
    }

    /**
     * 创建设置面板组件。
     * @return UI 组件
     */
    @Override
    public @Nullable JComponent createComponent() {
        ZaFridaSettingsComponent c = new ZaFridaSettingsComponent();
        c.reset(settingsService.getState());
        this.component = c;
        return c.getPanel();
    }

    /**
     * 判断配置是否被修改。
     * @return true 表示有修改
     */
    @Override
    public boolean isModified() {
        if (component == null) return false;

        ZaFridaSettingsState copy = new ZaFridaSettingsState();
        // start from current state
        // 从当前状态拷贝作为基准
        copy.fridaExecutable = settingsService.getState().fridaExecutable;
        copy.fridaPsExecutable = settingsService.getState().fridaPsExecutable;
        copy.fridaLsDevicesExecutable = settingsService.getState().fridaLsDevicesExecutable;
        copy.logsDirName = settingsService.getState().logsDirName;
        copy.defaultRemoteHost = settingsService.getState().defaultRemoteHost;
        copy.defaultRemotePort = settingsService.getState().defaultRemotePort;
        copy.useIdeScriptChooser = settingsService.getState().useIdeScriptChooser;
        copy.remoteHosts = settingsService.getRemoteHosts();

        component.applyTo(copy);

        // compare
        // 对比新旧配置
        ZaFridaSettingsState current = settingsService.getState();
        if (!safeEq(copy.fridaExecutable, current.fridaExecutable)) return true;
        if (!safeEq(copy.fridaPsExecutable, current.fridaPsExecutable)) return true;
        if (!safeEq(copy.fridaLsDevicesExecutable, current.fridaLsDevicesExecutable)) return true;
        if (!safeEq(copy.logsDirName, current.logsDirName)) return true;
        if (!safeEq(copy.defaultRemoteHost, current.defaultRemoteHost)) return true;
        if (copy.defaultRemotePort != current.defaultRemotePort) return true;
        if (copy.useIdeScriptChooser != current.useIdeScriptChooser) return true;

        if (copy.remoteHosts == null && current.remoteHosts != null && !current.remoteHosts.isEmpty()) return true;
        if (copy.remoteHosts != null && current.remoteHosts == null && !copy.remoteHosts.isEmpty()) return true;
        if (copy.remoteHosts != null && current.remoteHosts != null && !copy.remoteHosts.equals(current.remoteHosts)) return true;

        return false;
    }

    /**
     * 应用设置改动。
     */
    @Override
    public void apply() {
        if (component == null) return;
        ZaFridaSettingsState newState = new ZaFridaSettingsState();
        newState.fridaExecutable = settingsService.getState().fridaExecutable;
        newState.fridaPsExecutable = settingsService.getState().fridaPsExecutable;
        newState.fridaLsDevicesExecutable = settingsService.getState().fridaLsDevicesExecutable;
        newState.logsDirName = settingsService.getState().logsDirName;
        newState.defaultRemoteHost = settingsService.getState().defaultRemoteHost;
        newState.defaultRemotePort = settingsService.getState().defaultRemotePort;
        newState.useIdeScriptChooser = settingsService.getState().useIdeScriptChooser;
        newState.remoteHosts = settingsService.getRemoteHosts();

        component.applyTo(newState);
        settingsService.loadState(newState);
    }

    /**
     * 重置 UI 为当前持久化状态。
     */
    @Override
    public void reset() {
        if (component != null) {
            component.reset(settingsService.getState());
        }
    }

    /**
     * 释放 UI 资源。
     */
    @Override
    public void disposeUIResources() {
        component = null;
    }

    /**
     * 安全比较字符串相等性。
     * @param a 字符串 A
     * @param b 字符串 B
     * @return true 表示相等
     */
    private static boolean safeEq(String a, String b) {
        if (a == null) return b == null;
        return a.equals(b);
    }
}
