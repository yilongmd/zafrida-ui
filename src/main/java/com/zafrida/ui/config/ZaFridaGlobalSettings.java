package com.zafrida.ui.config;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.components.*;
import com.intellij.util.xmlb.XmlSerializerUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * [全局配置] IDE 级别的全局设置存储服务。
 * <p>
 * <strong>职责：</strong>
 * 1. 存储与特定项目无关的通用配置（如 Frida 工具链路径、默认连接端口、控制台外观）。
 * 2. 数据持久化到 IDE 配置目录下的 {@code zafrida-global.xml}。
 * <p>
 * <strong>区别：</strong>
 * 这里的配置对所有项目生效；而 {@link ZaFridaProjectSettings} 仅对当前项目生效。
 * <p>
 * <strong>关键逻辑：</strong>
 * 当 {@link com.zafrida.ui.python.ProjectPythonEnvResolver} 无法解析环境时，插件会回退使用这里配置的 {@code fridaPath} 等全局路径。
 */
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