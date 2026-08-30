package com.zafrida.ui.frida;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class FridaOutputParsersTest {

    @Test
    void parsesApplicationsByHeaderColumnsWhenLongestNameHasNoPadding() {
        String output = """
                  PID  Name                    Identifier
                -----  ----------------------  -----------------------
                 1234  Short                   com.example.short
                    -  Longest Application Name  com.example.long
                """;

        List<FridaProcess> processes = FridaOutputParsers.parseProcesses(output);

        assertEquals(2, processes.size());
        assertEquals(1234, processes.get(0).getPid());
        assertEquals("Short", processes.get(0).getName());
        assertEquals("com.example.short", processes.get(0).getIdentifier());
        assertNull(processes.get(1).getPid());
        assertEquals("Longest Application Name", processes.get(1).getName());
        assertEquals("com.example.long", processes.get(1).getIdentifier());
    }

    @Test
    void parsesRunningProcessTableWithoutIdentifierColumn() {
        String output = """
                  PID  Name
                -----  ----------------
                   42  system_server
                """;

        List<FridaProcess> processes = FridaOutputParsers.parseProcesses(output);

        assertEquals(1, processes.size());
        assertEquals(42, processes.get(0).getPid());
        assertEquals("system_server", processes.get(0).getName());
        assertNull(processes.get(0).getIdentifier());
    }

    @Test
    void stripsAnsiAndParsesDevices() {
        String output = "\u001b[32mId  Type  Name\u001b[0m\n"
                + "usb  usb  Pixel 8\n"
                + "local  local  Local System\n";

        List<FridaDevice> devices = FridaOutputParsers.parseDevices(output);

        assertEquals(2, devices.size());
        assertEquals("usb", devices.get(0).getId());
        assertEquals("Pixel 8", devices.get(0).getName());
    }
}
