package com.zafrida.ui.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ZaStrUtilTest {

    @Test
    void handlesProjectBlankCharactersAndTrim() {
        assertTrue(ZaStrUtil.isBlank(" \t\n\uFEFF"));
        assertFalse(ZaStrUtil.isBlank(" frida "));
        assertEquals("frida", ZaStrUtil.trim("\uFEFF frida \n"));
    }

    @Test
    void comparesNumericAndQualifiedVersions() {
        assertTrue(ZaStrUtil.compareVersion("17.0.0", "16.7.19") > 0);
        assertEquals(0, ZaStrUtil.compareVersion("17", "17.0.0"));
        assertTrue(ZaStrUtil.compareVersion("17.0.0-rc1", "17.0.0") > 0);
    }
}
