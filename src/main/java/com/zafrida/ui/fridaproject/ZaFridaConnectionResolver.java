package com.zafrida.ui.fridaproject;

import com.intellij.openapi.application.ApplicationManager;
import com.zafrida.ui.frida.FridaConnectionMode;
import com.zafrida.ui.frida.FridaConnectionPlan;
import com.zafrida.ui.frida.FridaDevice;
import com.zafrida.ui.settings.ZaFridaSettingsService;
import com.zafrida.ui.settings.ZaFridaSettingsState;
import com.zafrida.ui.util.ZaFridaNetUtil;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/** 把项目配置里的连接模式/端点与界面选中的设备合成 {@link FridaConnectionPlan}，并统一端点缺省值。 */
public final class ZaFridaConnectionResolver {

    private ZaFridaConnectionResolver() {
    }

    public static @NotNull FridaConnectionPlan resolve(@Nullable ZaFridaFridaProject fridaProject,
                                                       @Nullable ZaFridaProjectConfig config,
                                                       @Nullable FridaDevice selectedDevice) {
        return FridaConnectionPlan.resolve(
                resolveMode(config),
                resolveHost(config),
                resolvePort(config),
                selectedDevice,
                usesAdb(fridaProject)
        );
    }

    public static @NotNull FridaConnectionMode resolveMode(@Nullable ZaFridaProjectConfig config) {
        if (config == null || config.connectionMode == null) {
            return FridaConnectionMode.USB;
        }
        return config.connectionMode;
    }

    public static @NotNull String resolveHost(@Nullable ZaFridaProjectConfig config) {
        if (config != null && ZaStrUtil.isNotBlank(config.remoteHost)) {
            return config.remoteHost.trim();
        }
        return defaultHost();
    }

    public static int resolvePort(@Nullable ZaFridaProjectConfig config) {
        if (config != null && config.remotePort > 0) {
            return config.remotePort;
        }
        return defaultPort();
    }

    public static @NotNull String defaultHost() {
        return ZaFridaNetUtil.defaultHost(settingsState().defaultRemoteHost);
    }

    public static int defaultPort() {
        return ZaFridaNetUtil.defaultPort(settingsState().defaultRemotePort);
    }

    /** 是否需要 adb（拉起 server、端口转发）。没有活动项目时无法判断平台，沿用历史行为按 Android 处理。 */
    public static boolean usesAdb(@Nullable ZaFridaFridaProject fridaProject) {
        return fridaProject == null || fridaProject.getPlatform() == ZaFridaPlatform.ANDROID;
    }

    private static @NotNull ZaFridaSettingsState settingsState() {
        return ApplicationManager.getApplication().getService(ZaFridaSettingsService.class).getState();
    }
}
