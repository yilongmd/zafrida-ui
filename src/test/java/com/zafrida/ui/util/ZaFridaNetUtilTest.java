package com.zafrida.ui.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class ZaFridaNetUtilTest {

    @Test
    void parsesHostWithExplicitOrFallbackPort() {
        ZaFridaNetUtil.HostPort explicit = ZaFridaNetUtil.parseHostPort(" 192.168.1.20:27042 ", 14725);
        ZaFridaNetUtil.HostPort fallback = ZaFridaNetUtil.parseHostPort("localhost", 14725);

        assertNotNull(explicit);
        assertEquals("192.168.1.20", explicit.getHost());
        assertEquals(27042, explicit.getPort());
        assertNotNull(fallback);
        assertEquals("localhost:14725", fallback.toString());
    }

    @Test
    void rejectsMalformedEndpoints() {
        assertNull(ZaFridaNetUtil.parseHostPort("", 14725));
        assertNull(ZaFridaNetUtil.parseHostPort(":27042", 14725));
        assertNull(ZaFridaNetUtil.parseHostPort("host:", 14725));
        assertNull(ZaFridaNetUtil.parseHostPort("host:0", 14725));
        assertNull(ZaFridaNetUtil.parseHostPort("host:70000", 14725));
        assertNull(ZaFridaNetUtil.parseHostPort("host:abc", 14725));
        assertNull(ZaFridaNetUtil.parseHostPort("bad host:27042", 14725));
    }
}
