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

    /** frida 可执行文件路径 */
    public String fridaExecutable = "frida";
    /** frida-ps 可执行文件路径 */
    public String fridaPsExecutable = "frida-ps";
    /** frida-ls-devices 可执行文件路径 */
    public String fridaLsDevicesExecutable = "frida-ls-devices";
    /** 日志目录名 */
    public String logsDirName = "zafrida-logs";
    /** 远程主机历史列表 */
    public List<String> remoteHosts = new ArrayList<>();
    /** 默认远程主机 */
    public String defaultRemoteHost = "127.0.0.1";
    /** 默认远程端口 */
    public int defaultRemotePort = 14725;
    /** 是否使用 IDE 自带脚本选择器 */
    public boolean useIdeScriptChooser = true;
}
