package com.zafrida.ui.toolwindow;

import com.intellij.openapi.util.BuildNumber;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

final class ZaFridaPluginUpdateServiceTest {

    @Test
    void findsLatestVersionCompatibleWithCurrentIdeBuild() {
        String response = """
                <plugin-repository>
                  <category name="Tools">
                    <idea-plugin>
                      <id>com.zafrida.ui</id>
                      <version>0.3.8</version>
                      <idea-version since-build="243.100"/>
                    </idea-plugin>
                    <idea-plugin>
                      <id>com.zafrida.ui</id>
                      <version>0.4.0</version>
                      <idea-version since-build="251.1"/>
                    </idea-plugin>
                    <idea-plugin>
                      <id>another.plugin</id>
                      <version>9.0.0</version>
                      <idea-version since-build="243.1"/>
                    </idea-plugin>
                  </category>
                </plugin-repository>
                """;
        BuildNumber currentBuild = BuildNumber.fromString("PY-243.21565");
        assertNotNull(currentBuild);

        String latest = ZaFridaPluginUpdateService.findLatestCompatibleVersion(response, currentBuild);

        assertEquals("0.3.8", latest);
    }

    @Test
    void rejectsVersionAboveUntilBuild() {
        String response = """
                <plugin-repository>
                  <idea-plugin>
                    <id>com.zafrida.ui</id>
                    <version>0.3.8</version>
                    <idea-version since-build="242" until-build="242.*"/>
                  </idea-plugin>
                </plugin-repository>
                """;
        BuildNumber currentBuild = BuildNumber.fromString("PY-243.21565");
        assertNotNull(currentBuild);

        String latest = ZaFridaPluginUpdateService.findLatestCompatibleVersion(response, currentBuild);

        assertNull(latest);
    }
}
