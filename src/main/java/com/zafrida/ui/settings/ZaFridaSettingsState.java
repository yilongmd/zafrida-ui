package com.zafrida.ui.settings;

import java.util.ArrayList;
import java.util.List;

public final class ZaFridaSettingsState {

    public static final String TEMPLATE_ROOT_MODE_SYSTEM = "SYSTEM";
    public static final String TEMPLATE_ROOT_MODE_IDE = "IDE";
    public static final int DEFAULT_SKILLS_API_PORT = 17839;

    public String fridaExecutable = "frida";
    public String fridaPsExecutable = "frida-ps";
    public String fridaLsDevicesExecutable = "frida-ls-devices";
    public String fridaVersion = "16";
    public String vscodeExecutable = "";
    public String editor010Executable = "";
    public String logsDirName = "zafrida-logs";
    public List<String> remoteHosts = new ArrayList<>();
    public String defaultRemoteHost = "127.0.0.1";
    public int defaultRemotePort = 14725;
    public boolean useIdeScriptChooser = true;
    public String templatesRootMode = TEMPLATE_ROOT_MODE_SYSTEM;
    public boolean enableSkillsHttpApi = false;
    public int skillsApiPort = DEFAULT_SKILLS_API_PORT;
}
