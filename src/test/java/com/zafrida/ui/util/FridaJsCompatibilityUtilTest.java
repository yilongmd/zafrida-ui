package com.zafrida.ui.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FridaJsCompatibilityUtilTest {

    @Test
    void convertsGlobalExportForFrida17() {
        String source = "Module.findExportByName(null, \"open\")";

        String result = FridaJsCompatibilityUtil.adaptForFridaVersion(source, true);

        assertEquals("Module.getGlobalExportByName(\"open\")", result);
    }

    @Test
    void convertsNamedModuleExportForFrida17() {
        String source = "Module.findExportByName('libc.so', 'open')";

        String result = FridaJsCompatibilityUtil.adaptForFridaVersion(source, true);

        assertEquals("Process.getModuleByName('libc.so').getExportByName('open')", result);
    }

    @Test
    void leavesFrida16ScriptUnchanged() {
        String source = "Module.findExportByName(null, \"open\")";

        String result = FridaJsCompatibilityUtil.adaptForFridaVersion(source, false);

        assertEquals(source, result);
    }
}
