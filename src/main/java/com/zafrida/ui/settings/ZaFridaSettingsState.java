package com.zafrida.ui.settings;

import java.util.ArrayList;
import java.util.List;
/**
 * [DTO] 全局配置数据模型。
 * <p>
 * <strong>数据流：</strong>
 * 映射到 IDE 配置目录下的 {@code zafrida.xml} 文件。
 * 存储不随项目改变的通用设置，如 frida 二进制文件路径和常用远程主机列表。
 */
public final class ZaFridaSettingsState {

    public String fridaExecutable = "frida";
    public String fridaPsExecutable = "frida-ps";
    public String fridaLsDevicesExecutable = "frida-ls-devices";
    public String logsDirName = "zafrida-logs";
    public List<String> remoteHosts = new ArrayList<>();
    public String defaultRemoteHost = "127.0.0.1";
    public int defaultRemotePort = 14725;
    public boolean useIdeScriptChooser = true;
}
