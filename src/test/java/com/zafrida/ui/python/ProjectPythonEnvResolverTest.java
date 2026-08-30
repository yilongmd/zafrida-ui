package com.zafrida.ui.python;

import com.intellij.openapi.util.SystemInfoRt;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ProjectPythonEnvResolverTest {

    @TempDir
    Path tempDirectory;

    @Test
    void resolvesCommonLocalEnvironmentLayouts() throws Exception {
        List<String> environmentNames = List.of("venv", "virtualenv", "conda", "uv", "poetry", "pipenv", "hatch");

        for (String environmentName : environmentNames) {
            Path environmentRoot = tempDirectory.resolve(environmentName);
            Path interpreter = createInterpreter(environmentRoot);

            PythonEnvInfo environment = ProjectPythonEnvResolver.resolveConfiguredPath(environmentRoot.toString());

            assertEquals(interpreter.toAbsolutePath().normalize().toString(), environment.getPythonHome());
            assertEquals(environmentRoot.toAbsolutePath().normalize().toString(), environment.getEnvRoot());
            assertEquals(PythonEnvInfo.Source.ZAFRIDA_PROJECT, environment.getSource());
        }
    }

    @Test
    void resolvesInterpreterFileAndToolsFromSameEnvironment() throws Exception {
        Path environmentRoot = tempDirectory.resolve("shared-frida-17");
        Path interpreter = createInterpreter(environmentRoot);
        Path toolDirectory = interpreter.getParent();
        String fridaExecutableName = "frida";
        if (SystemInfoRt.isWindows) {
            fridaExecutableName = "frida.exe";
        }
        Path fridaTool = toolDirectory.resolve(fridaExecutableName);
        Files.createFile(fridaTool);

        PythonEnvInfo firstProject = ProjectPythonEnvResolver.resolveConfiguredPath(interpreter.toString());
        PythonEnvInfo secondProject = ProjectPythonEnvResolver.resolveConfiguredPath(environmentRoot.toString());

        assertEquals(firstProject.getEnvRoot(), secondProject.getEnvRoot());
        assertEquals(fridaTool.toAbsolutePath().normalize().toString(),
                ProjectPythonEnvResolver.findTool(firstProject, "frida"));
    }

    @Test
    void rejectsMissingAndRelativePaths() {
        assertThrows(PythonEnvResolutionException.class,
                () -> ProjectPythonEnvResolver.resolveConfiguredPath(tempDirectory.resolve("missing").toString()));
        assertThrows(PythonEnvResolutionException.class,
                () -> ProjectPythonEnvResolver.resolveConfiguredPath(".venv"));
    }

    private Path createInterpreter(Path environmentRoot) throws Exception {
        Path interpreter;
        if (SystemInfoRt.isWindows) {
            interpreter = environmentRoot.resolve("Scripts").resolve("python.exe");
        } else {
            interpreter = environmentRoot.resolve("bin").resolve("python");
        }
        Files.createDirectories(interpreter.getParent());
        Files.createFile(interpreter);
        assertTrue(Files.isRegularFile(interpreter));
        return interpreter;
    }
}
