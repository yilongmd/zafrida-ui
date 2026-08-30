package com.zafrida.ui.fridaproject;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ZaFridaProjectStorageTest {

    private final ZaFridaProjectStorage storage = new ZaFridaProjectStorage();

    @Test
    void oldProjectXmlDefaultsToIdePythonEnvironment() throws Exception {
        String xml = "<zafridaProject version=\"1\" name=\"legacy\" platform=\"ANDROID\"/>";

        ZaFridaProjectConfig config = storage.parseProject(xml);

        assertEquals("", config.pythonEnvironmentPath);
    }

    @Test
    void pythonEnvironmentPathRoundTripsWithoutChangingExistingFields() throws Exception {
        ZaFridaProjectConfig config = new ZaFridaProjectConfig();
        config.name = "shared";
        config.pythonEnvironmentPath = "/opt/frida-envs/frida-17";
        config.extraArgs = "--realm=native";

        String xml = storage.toProjectXml(config);
        ZaFridaProjectConfig loaded = storage.parseProject(xml);

        assertTrue(xml.contains("version=\"2\""));
        assertEquals(config.pythonEnvironmentPath, loaded.pythonEnvironmentPath);
        assertEquals(config.extraArgs, loaded.extraArgs);
    }

    @Test
    void malformedEnumsFallBackInsteadOfDiscardingProject() throws Exception {
        String xml = "<zafridaProject name=\"legacy\" platform=\"UNKNOWN\" "
                + "connectionMode=\"BROKEN\" processScope=\"BROKEN\"/>";

        ZaFridaProjectConfig config = storage.parseProject(xml);

        assertEquals(ZaFridaPlatform.ANDROID, config.platform);
        assertEquals("", config.pythonEnvironmentPath);
    }

    @Test
    void rejectsDoctypeAndExternalEntities() {
        String xml = "<!DOCTYPE zafridaProject [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
                + "<zafridaProject name=\"&xxe;\" platform=\"ANDROID\"/>";

        assertThrows(Exception.class, () -> storage.parseProject(xml));
    }

    @Test
    void workspaceIgnoresTraversalAndDuplicateEntries() throws Exception {
        String xml = """
                <zafridaWorkspace>
                  <project name="safe" platform="ANDROID" relativeDir="android/safe"/>
                  <project name="outside" platform="ANDROID" relativeDir="../outside"/>
                  <project name="safe" platform="IOS" relativeDir="ios/duplicate-name"/>
                  <project name="duplicate-dir" platform="IOS" relativeDir="android/safe"/>
                  <project name="normalized-duplicate" platform="IOS" relativeDir="android/tmp/../safe"/>
                </zafridaWorkspace>
                """;

        ZaFridaWorkspaceConfig config = storage.parseWorkspace(xml);

        assertEquals(1, config.projects.size());
        assertEquals("safe", config.projects.get(0).getName());
    }

    @Test
    void unsafeScriptPathsFallBackInsideProject() throws Exception {
        String xml = "<zafridaProject name=\"demo\" platform=\"ANDROID\" "
                + "mainScript=\"../../outside.js\" attachScript=\"/tmp/attach.ts\" remotePort=\"70000\"/>";

        ZaFridaProjectConfig config = storage.parseProject(xml);

        assertEquals("demo.js", config.mainScript);
        assertEquals("", config.attachScript);
        assertEquals(14725, config.remotePort);
    }

    @Test
    void defaultScriptNamePreservesTypeScriptExtension() {
        assertEquals("agent.ts", ZaFridaProjectFiles.defaultMainScriptName("agent.ts"));
    }
}
