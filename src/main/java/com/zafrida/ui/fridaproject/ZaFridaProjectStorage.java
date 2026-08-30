package com.zafrida.ui.fridaproject;

import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.project.ProjectUtil;
import com.intellij.openapi.util.JDOMUtil;
import com.intellij.openapi.vfs.VfsUtil;
import com.intellij.openapi.vfs.VfsUtilCore;
import com.intellij.openapi.vfs.VirtualFile;
import com.zafrida.ui.frida.FridaConnectionMode;
import com.zafrida.ui.frida.FridaProcessScope;
import com.zafrida.ui.util.ZaStrUtil;
import org.jdom.Document;
import org.jdom.Element;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashSet;
import java.util.Set;

public final class ZaFridaProjectStorage {

    private static final Logger LOG = Logger.getInstance(ZaFridaProjectStorage.class);

    public @NotNull ZaFridaWorkspaceConfig loadWorkspace(@NotNull Project project) {
        VirtualFile base = ProjectUtil.guessProjectDir(project);
        if (base == null) {
            return new ZaFridaWorkspaceConfig();
        }
        VirtualFile file = base.findChild(ZaFridaProjectFiles.WORKSPACE_FILE);
        if (file == null) {
            return new ZaFridaWorkspaceConfig();
        }
        try {
            String xml = VfsUtilCore.loadText(file);
            return parseWorkspace(xml);
        } catch (Exception t) {
            LOG.warn(String.format("Load ZAFrida workspace failed: %s", file.getPath()), t);
            return new ZaFridaWorkspaceConfig();
        }
    }

    public void saveWorkspace(@NotNull Project project, @NotNull ZaFridaWorkspaceConfig cfg) {
        VirtualFile base = ProjectUtil.guessProjectDir(project);
        if (base == null) {
            return;
        }
        WriteCommandAction.runWriteCommandAction(project, () -> {
            try {
                VirtualFile file = base.findChild(ZaFridaProjectFiles.WORKSPACE_FILE);
                if (file == null) {
                    file = base.createChildData(this, ZaFridaProjectFiles.WORKSPACE_FILE);
                }
                VfsUtil.saveText(file, toWorkspaceXml(cfg));
            } catch (Exception t) {
                LOG.warn(String.format("Save ZAFrida workspace failed: %s", base.getPath()), t);
                throw new IllegalStateException("Save ZAFrida workspace failed", t);
            }
        });
    }

    public @NotNull ZaFridaProjectConfig loadProjectConfig(@NotNull Project project, @NotNull VirtualFile fridaProjectDir) {
        VirtualFile f = fridaProjectDir.findChild(ZaFridaProjectFiles.PROJECT_FILE);
        if (f == null) {
            ZaFridaProjectConfig c = new ZaFridaProjectConfig();
            c.name = fridaProjectDir.getName();
            c.mainScript = ZaFridaProjectFiles.defaultMainScriptName(c.name);
            return c;
        }
        try {
            String xml = VfsUtilCore.loadText(f);
            return parseProject(xml);
        } catch (Exception t) {
            LOG.warn(String.format("Load ZAFrida project config failed: %s", f.getPath()), t);
            ZaFridaProjectConfig c = new ZaFridaProjectConfig();
            c.name = fridaProjectDir.getName();
            c.mainScript = ZaFridaProjectFiles.defaultMainScriptName(c.name);
            return c;
        }
    }

    public void saveProjectConfig(@NotNull Project project, @NotNull VirtualFile fridaProjectDir, @NotNull ZaFridaProjectConfig cfg) {
        WriteCommandAction.runWriteCommandAction(project, () -> {
            try {
                VirtualFile f = fridaProjectDir.findChild(ZaFridaProjectFiles.PROJECT_FILE);
                if (f == null) {
                    f = fridaProjectDir.createChildData(this, ZaFridaProjectFiles.PROJECT_FILE);
                }
                VfsUtil.saveText(f, toProjectXml(cfg));
            } catch (Exception t) {
                LOG.warn(String.format("Save ZAFrida project config failed: %s", fridaProjectDir.getPath()), t);
                throw new IllegalStateException("Save ZAFrida project config failed", t);
            }
        });
    }

    public @Nullable String relativize(@NotNull VirtualFile baseDir, @NotNull VirtualFile file) {
        return VfsUtilCore.getRelativePath(file, baseDir, '/');
    }

    ZaFridaWorkspaceConfig parseWorkspace(String xml) throws Exception {
        Element root = parseXmlRoot(xml);
        if (!"zafridaWorkspace".equals(root.getName())) {
            throw new IllegalArgumentException(String.format("Unexpected workspace root element: %s", root.getName()));
        }
        ZaFridaWorkspaceConfig cfg = new ZaFridaWorkspaceConfig();
        cfg.lastSelected = root.getAttributeValue("lastSelected");

        Set<String> names = new HashSet<>();
        Set<String> directories = new HashSet<>();
        for (Element p : root.getChildren("project")) {
            String name = p.getAttributeValue("name");
            String platform = p.getAttributeValue("platform");
            String rawRelativeDir = p.getAttributeValue("relativeDir");
            String relDir = normalizeSafeRelativePath(rawRelativeDir);
            if (ZaStrUtil.isBlank(name) || platform == null || relDir == null) {
                LOG.warn(String.format("Ignore invalid ZAFrida workspace project: name=%s relativeDir=%s", name, rawRelativeDir));
                continue;
            }
            name = name.trim();
            if (!names.add(name) || !directories.add(relDir)) {
                LOG.warn(String.format("Ignore duplicate ZAFrida workspace project: name=%s relativeDir=%s", name, relDir));
                continue;
            }
            ZaFridaPlatform parsedPlatform = parseEnum(
                    ZaFridaPlatform.class,
                    platform,
                    ZaFridaPlatform.ANDROID,
                    "workspace platform"
            );
            cfg.projects.add(new ZaFridaFridaProject(name, parsedPlatform, relDir));
        }
        return cfg;
    }

    private String toWorkspaceXml(ZaFridaWorkspaceConfig cfg) {
        Element root = new Element("zafridaWorkspace");
        root.setAttribute("version", String.valueOf(ZaFridaWorkspaceConfig.VERSION));
        if (cfg.lastSelected != null) {
            root.setAttribute("lastSelected", cfg.lastSelected);
        }

        for (ZaFridaFridaProject p : cfg.projects) {
            Element e = new Element("project");
            e.setAttribute("name", p.getName());
            e.setAttribute("platform", p.getPlatform().name());
            e.setAttribute("relativeDir", p.getRelativeDir());
            root.addContent(e);
        }
        return JDOMUtil.writeDocument(new Document(root), "\n");
    }

    ZaFridaProjectConfig parseProject(String xml) throws Exception {
        Element root = parseXmlRoot(xml);
        if (!"zafridaProject".equals(root.getName())) {
            throw new IllegalArgumentException(String.format("Unexpected project root element: %s", root.getName()));
        }
        ZaFridaProjectConfig cfg = new ZaFridaProjectConfig();
        cfg.name = root.getAttributeValue("name", "");
        cfg.platform = parseEnum(
                ZaFridaPlatform.class,
                root.getAttributeValue("platform", ZaFridaPlatform.ANDROID.name()),
                ZaFridaPlatform.ANDROID,
                "project platform"
        );
        String mainScriptAttr = root.getAttributeValue("mainScript");
        if (ZaStrUtil.isBlank(mainScriptAttr)) {
            cfg.mainScript = ZaFridaProjectFiles.defaultMainScriptName(cfg.name);
        } else {
            String mainScript = normalizeSafeRelativePath(mainScriptAttr);
            if (mainScript == null) {
                LOG.warn(String.format("Ignore unsafe ZAFrida main script path: %s", mainScriptAttr));
                cfg.mainScript = ZaFridaProjectFiles.defaultMainScriptName(cfg.name);
            } else {
                cfg.mainScript = mainScript;
            }
        }
        String attachScriptAttr = root.getAttributeValue("attachScript", "");
        if (ZaStrUtil.isBlank(attachScriptAttr)) {
            cfg.attachScript = "";
        } else {
            String attachScript = normalizeSafeRelativePath(attachScriptAttr);
            if (attachScript == null) {
                LOG.warn(String.format("Ignore unsafe ZAFrida attach script path: %s", attachScriptAttr));
                cfg.attachScript = "";
            } else {
                cfg.attachScript = attachScript;
            }
        }
        cfg.lastTarget = root.getAttributeValue("lastTarget");
        cfg.spawnMode = Boolean.parseBoolean(root.getAttributeValue("spawnMode", "true"));
        cfg.extraArgs = root.getAttributeValue("extraArgs", "");
        cfg.targetManual = Boolean.parseBoolean(root.getAttributeValue("targetManual", "true"));
        cfg.processScope = parseEnum(
                FridaProcessScope.class,
                root.getAttributeValue("processScope", FridaProcessScope.RUNNING_APPS.name()),
                FridaProcessScope.RUNNING_APPS,
                "process scope"
        );
        cfg.connectionMode = parseEnum(
                FridaConnectionMode.class,
                root.getAttributeValue("connectionMode", FridaConnectionMode.USB.name()),
                FridaConnectionMode.USB,
                "connection mode"
        );

        cfg.remoteHost = root.getAttributeValue("remoteHost", "127.0.0.1");
        cfg.remotePort = parsePort(root.getAttributeValue("remotePort"), 14725);
        cfg.lastDeviceId = root.getAttributeValue("lastDeviceId");
        cfg.lastDeviceHost = root.getAttributeValue("lastDeviceHost");
        cfg.pythonEnvironmentPath = root.getAttributeValue("pythonEnvironmentPath", "");
        return cfg;
    }

    String toProjectXml(ZaFridaProjectConfig cfg) {
        Element root = new Element("zafridaProject");
        root.setAttribute("version", String.valueOf(ZaFridaProjectConfig.VERSION));
        root.setAttribute("name", cfg.name);
        root.setAttribute("platform", cfg.platform.name());
        root.setAttribute("mainScript", cfg.mainScript);
        root.setAttribute("attachScript", nonNull(cfg.attachScript));
        root.setAttribute("spawnMode", String.valueOf(cfg.spawnMode));
        root.setAttribute("extraArgs", nonNull(cfg.extraArgs));
        if (cfg.lastTarget != null) {
            root.setAttribute("lastTarget", cfg.lastTarget);
        }
        root.setAttribute("targetManual", String.valueOf(cfg.targetManual));
        root.setAttribute("processScope", cfg.processScope.name());
        root.setAttribute("connectionMode", cfg.connectionMode.name());
        root.setAttribute("remoteHost", cfg.remoteHost);
        root.setAttribute("remotePort", String.valueOf(cfg.remotePort));
        if (cfg.lastDeviceId != null) {
            root.setAttribute("lastDeviceId", cfg.lastDeviceId);
        }
        if (cfg.lastDeviceHost != null) {
            root.setAttribute("lastDeviceHost", cfg.lastDeviceHost);
        }
        if (ZaStrUtil.isNotBlank(cfg.pythonEnvironmentPath)) {
            root.setAttribute("pythonEnvironmentPath", cfg.pythonEnvironmentPath.trim());
        }
        return JDOMUtil.writeDocument(new Document(root), "\n");
    }

    private static int parsePort(@Nullable String value, int fallback) {
        if (ZaStrUtil.isBlank(value)) {
            return fallback;
        }
        try {
            int port = Integer.parseInt(value.trim());
            if (port > 0 && port <= 65_535) {
                return port;
            }
            return fallback;
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    // 调用方必须已持有 write action。
    public void saveWorkspaceNoWriteAction(@NotNull VirtualFile baseDir, @NotNull ZaFridaWorkspaceConfig cfg) {
        try {
            VirtualFile file = baseDir.findChild(ZaFridaProjectFiles.WORKSPACE_FILE);
            if (file == null) {
                file = baseDir.createChildData(this, ZaFridaProjectFiles.WORKSPACE_FILE);
            }
            VfsUtil.saveText(file, toWorkspaceXml(cfg));
        } catch (Exception t) {
            LOG.warn(String.format("Save ZAFrida workspace in write action failed: %s", baseDir.getPath()), t);
            throw new IllegalStateException("Save ZAFrida workspace failed", t);
        }
    }

    // 调用方必须已持有 write action。
    public void saveProjectConfigNoWriteAction(@NotNull VirtualFile fridaProjectDir, @NotNull ZaFridaProjectConfig cfg) {
        try {
            VirtualFile f = fridaProjectDir.findChild(ZaFridaProjectFiles.PROJECT_FILE);
            if (f == null) {
                f = fridaProjectDir.createChildData(this, ZaFridaProjectFiles.PROJECT_FILE);
            }
            VfsUtil.saveText(f, toProjectXml(cfg));
        } catch (Exception t) {
            LOG.warn(String.format("Save ZAFrida project config in write action failed: %s", fridaProjectDir.getPath()), t);
            throw new IllegalStateException("Save ZAFrida project config failed", t);
        }
    }

    private static @NotNull String nonNull(@Nullable String value) {
        if (value == null) {
            return "";
        }
        return value;
    }

    private static <E extends Enum<E>> @NotNull E parseEnum(@NotNull Class<E> type,
                                                             @Nullable String value,
                                                             @NotNull E fallback,
                                                             @NotNull String fieldName) {
        if (ZaStrUtil.isBlank(value)) {
            return fallback;
        }
        try {
            return Enum.valueOf(type, value.trim());
        } catch (IllegalArgumentException e) {
            LOG.warn(String.format("Unknown ZAFrida %s value '%s'; using %s", fieldName, value, fallback.name()));
            return fallback;
        }
    }

    private static @NotNull Element parseXmlRoot(@NotNull String xml) throws Exception {
        return JDOMUtil.load(xml);
    }

    private static @Nullable String normalizeSafeRelativePath(@Nullable String value) {
        if (ZaStrUtil.isBlank(value)) {
            return null;
        }
        try {
            String normalizedSeparators = value.trim().replace('\\', '/');
            if (normalizedSeparators.length() >= 3
                    && Character.isLetter(normalizedSeparators.charAt(0))
                    && normalizedSeparators.charAt(1) == ':'
                    && normalizedSeparators.charAt(2) == '/') {
                return null;
            }
            Path path = Paths.get(normalizedSeparators);
            if (path.isAbsolute()) {
                return null;
            }
            Path normalized = path.normalize();
            if (normalized.getNameCount() == 0 || normalized.toString().isEmpty() || ".".equals(normalized.toString())) {
                return null;
            }
            if ("..".equals(normalized.getName(0).toString())) {
                return null;
            }
            return normalized.toString().replace('\\', '/');
        } catch (InvalidPathException e) {
            return null;
        }
    }

}
