package com.zafrida.ui.settings;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ZaFridaSettingsServiceTest {

    @Test
    void normalizesLegacyAndMalformedState() {
        ZaFridaSettingsState loaded = new ZaFridaSettingsState();
        loaded.fridaExecutable = null;
        loaded.fridaPsExecutable = " ";
        loaded.fridaLsDevicesExecutable = null;
        loaded.logsDirName = "";
        loaded.defaultRemoteHost = null;
        loaded.defaultRemotePort = -1;
        loaded.skillsApiPort = 80_000;
        loaded.templatesRootMode = "unknown";
        loaded.remoteHosts = Arrays.asList(" host:1234 ", "", null, "host:1234");

        ZaFridaSettingsService service = new ZaFridaSettingsService();
        service.loadState(loaded);
        ZaFridaSettingsState state = service.getState();

        assertEquals("frida", state.fridaExecutable);
        assertEquals("frida-ps", state.fridaPsExecutable);
        assertEquals("frida-ls-devices", state.fridaLsDevicesExecutable);
        assertEquals("zafrida-logs", state.logsDirName);
        assertEquals("127.0.0.1", state.defaultRemoteHost);
        assertEquals(14725, state.defaultRemotePort);
        assertEquals(ZaFridaSettingsState.DEFAULT_SKILLS_API_PORT, state.skillsApiPort);
        assertEquals(ZaFridaSettingsState.TEMPLATE_ROOT_MODE_SYSTEM, state.templatesRootMode);
        assertEquals(List.of("host:1234"), state.remoteHosts);
    }
}
