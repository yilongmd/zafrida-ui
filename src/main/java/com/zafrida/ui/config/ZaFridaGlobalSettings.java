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

    /** Frida 工具链路径配置(默认使用当前PyCharm IDE中Python Interpreter的venv/conda) */
    public String fridaPath = "frida";
    /** Python 可执行文件路径配置(默认使用当前PyCharm IDE中Python Interpreter的venv/conda) */
    public String pythonPath = "python3";
    /** frida-ps 工具链路径配置 */
    public String fridaPsPath = "frida-ps";
    /** frida-ls-devices 工具链路径配置 */
    public String fridaLsDevicesPath = "frida-ls-devices";

    /** 默认远程主机地址(127.0.0.1方便通过USB等转发到本地端口) */
    public String defaultRemoteHost = "127.0.0.1";
    /** 默认远程连接端口 */
    public int defaultRemotePort = 14725;

    /** 控制台外观配置：最大行数 */
    public int maxConsoleLines = 10000;
    /** 控制台外观配置：自动滚动 */
    public boolean autoScrollConsole = true;
    /** 控制台外观配置：字体大小 */
    public int consoleFontSize = 12;

    /** 脚本模板配置：自动同步内置模板 */
    public boolean autoSyncTemplates = true;
    /** 脚本模板配置：显示键盘提示 */
    public boolean showKeyboardHints = true;
    /** 调试输出模式：启用后会在日志中打印更多调试信息 */
    public boolean verboseMode = false;

    /** 设备列表刷新配置：刷新间隔秒数 */
    public int refreshDeviceIntervalSeconds = 5;
    /** 设备列表刷新配置：是否自动刷新 */
    public boolean autoRefreshDevices = false;

    /**
     * 获取全局唯一实例。
     * @return ZaFridaGlobalSettings
     */
    public static ZaFridaGlobalSettings getInstance() {
        return ApplicationManager.getApplication().getService(ZaFridaGlobalSettings.class);
    }

    /**
     * 获取当前状态以便持久化。
     * @return Nullable ZaFridaGlobalSettings
     */
    @Override
    public @Nullable ZaFridaGlobalSettings getState() {
        return this;
    }

    /**
     * 加载持久化状态。
     * @param state NotNull ZaFridaGlobalSettings
     */
    @Override
    public void loadState(@NotNull ZaFridaGlobalSettings state) {
        XmlSerializerUtil.copyBean(state, this);
    }
}