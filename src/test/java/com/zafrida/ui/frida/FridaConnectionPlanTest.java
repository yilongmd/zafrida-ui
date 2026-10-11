package com.zafrida.ui.frida;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FridaConnectionPlanTest {

    private static final String LOOPBACK = "127.0.0.1";
    private static final int PORT = 14725;

    private final FridaDevice pixel = new FridaDevice("1A2B3C4D", "usb", "Pixel 6");
    private final FridaDevice local = new FridaDevice("local", "local", "Local System");

    @Test
    void usbModeUsesSelectedDeviceForFridaAndAdb() {
        FridaConnectionPlan plan = FridaConnectionPlan.resolve(FridaConnectionMode.USB, LOOPBACK, PORT, pixel, true);

        assertSame(pixel, plan.getFridaDevice());
        assertEquals("1A2B3C4D", plan.getAdbSerial());
        assertFalse(plan.isAdbForwardRequired());
        assertNull(plan.getSessionBlocker());
        assertEquals("frida -D 1A2B3C4D", plan.getSummary());
    }

    @Test
    void usbModeWithoutDeviceBlocksSessionOnly() {
        FridaConnectionPlan plan = FridaConnectionPlan.resolve(FridaConnectionMode.USB, LOOPBACK, PORT, null, true);

        assertNull(plan.getFridaDevice());
        assertNotNull(plan.getSessionBlocker());
        assertNull(plan.getAdbBlocker());
    }

    @Test
    void gadgetLoopbackForwardsToSelectedDeviceNotToEndpoint() {
        FridaConnectionPlan plan = FridaConnectionPlan.resolve(FridaConnectionMode.GADGET, LOOPBACK, PORT, pixel, true);

        FridaDevice fridaDevice = plan.getFridaDevice();
        assertNotNull(fridaDevice);
        assertEquals(List.of("-H", "127.0.0.1:14725"), fridaDevice.cliArgs());
        assertTrue(plan.isGadget());
        assertTrue(plan.isAdbForwardRequired());
        assertEquals(PORT, plan.getForwardPort());
        assertEquals("1A2B3C4D", plan.getAdbSerial());
        assertEquals("adb -s 1A2B3C4D forward tcp:14725 → frida -H 127.0.0.1:14725 -F", plan.getSummary());
    }

    @Test
    void remoteNonLoopbackSkipsForwardButKeepsAdbSerial() {
        FridaConnectionPlan plan = FridaConnectionPlan.resolve(FridaConnectionMode.REMOTE, "192.168.1.20", 27042, pixel, true);

        assertFalse(plan.isAdbForwardRequired());
        assertEquals("1A2B3C4D", plan.getAdbSerial());
        assertNull(plan.getSessionBlocker());
        assertEquals("frida -H 192.168.1.20:27042 · no adb forward", plan.getSummary());
    }

    @Test
    void notConnectedDeviceBlocksSessionWhenRouteNeedsIt() {
        FridaDevice missing = FridaDevice.notConnected("OLD-SERIAL");

        FridaConnectionPlan usb = FridaConnectionPlan.resolve(FridaConnectionMode.USB, LOOPBACK, PORT, missing, true);
        FridaConnectionPlan gadget = FridaConnectionPlan.resolve(FridaConnectionMode.GADGET, LOOPBACK, PORT, missing, true);

        assertNotNull(usb.getSessionBlocker());
        assertNull(usb.getFridaDevice());
        assertNotNull(gadget.getSessionBlocker());
        assertNotNull(gadget.getAdbBlocker());
        assertNull(gadget.getAdbSerial());
    }

    @Test
    void notConnectedDeviceOnlyBlocksAdbWhenRouteDoesNotNeedIt() {
        FridaDevice missing = FridaDevice.notConnected("OLD-SERIAL");

        FridaConnectionPlan plan = FridaConnectionPlan.resolve(FridaConnectionMode.REMOTE, "192.168.1.20", 27042, missing, true);

        assertNull(plan.getSessionBlocker());
        assertNotNull(plan.getAdbBlocker());
        assertNull(plan.getAdbSerial());
    }

    @Test
    void loopbackWithoutSelectionForwardsWithoutSerial() {
        FridaConnectionPlan plan = FridaConnectionPlan.resolve(FridaConnectionMode.REMOTE, "localhost", PORT, null, true);

        assertTrue(plan.isAdbForwardRequired());
        assertNull(plan.getAdbSerial());
        assertNull(plan.getSessionBlocker());
        assertEquals("adb forward tcp:14725 → frida -H localhost:14725", plan.getSummary());
    }

    @Test
    void nonUsbSelectionStillForwardsButWithoutSerial() {
        FridaConnectionPlan plan = FridaConnectionPlan.resolve(FridaConnectionMode.REMOTE, LOOPBACK, PORT, local, true);

        assertTrue(plan.isAdbForwardRequired());
        assertNull(plan.getAdbSerial());
    }

    @Test
    void nonAndroidProjectsSkipForward() {
        FridaConnectionPlan plan = FridaConnectionPlan.resolve(FridaConnectionMode.REMOTE, LOOPBACK, PORT, pixel, false);

        assertFalse(plan.isAdbForwardRequired());
    }

    @Test
    void genericUsbIdIsNotAnAdbSerial() {
        FridaDevice generic = new FridaDevice("usb", "usb", "Android");

        FridaConnectionPlan plan = FridaConnectionPlan.resolve(FridaConnectionMode.USB, LOOPBACK, PORT, generic, true);

        assertNull(plan.getAdbSerial());
        assertEquals("frida -U", plan.getSummary());
    }

    @Test
    void notConnectedPlaceholderNeverBecomesCliArgs() {
        FridaDevice missing = FridaDevice.notConnected("OLD-SERIAL");

        assertFalse(missing.isUsb());
        assertThrows(IllegalArgumentException.class, missing::cliArgs);
    }
}
