package com.zafrida.ui.fridaproject;

import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VfsUtil;
import com.intellij.openapi.vfs.VfsUtilCore;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.util.SlowOperations;
import com.zafrida.ui.frida.FridaConnectionMode;
import com.zafrida.ui.frida.FridaProcessScope;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.jdom.output.Format;
import org.jdom.output.XMLOutputter;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

/**
 * [数据层] XML 配置文件读写引擎。
 * <p>
 * 负责 {@code zafrida-workspace.xml} 和 {@code zafrida-project.xml} 的序列化与反序列化。
 * <p>
 * <strong>规范：</strong>
 * 1. 所有写操作必须在 {@link WriteCommandAction} 或 {@link com.intellij.util.SlowOperations} 中执行。
 * 2. 使用 JDOM 解析 XML。
 */
public final class ZaFridaProjectStorage {

    public @NotNull ZaFridaWorkspaceConfig loadWorkspace(@NotNull Project project) {
        final ZaFridaWorkspaceConfig[] out = new ZaFridaWorkspaceConfig[]{new ZaFridaWorkspaceConfig()};
        SlowOperations.allowSlowOperations(() -> {
            VirtualFile base = project.getBaseDir();
            if (base == null) return;
            VirtualFile file = base.findChild(ZaFridaProjectFiles.WORKSPACE_FILE);
            if (file == null) return;
            try {
                String xml = VfsUtilCore.loadText(file);
                out[0] = parseWorkspace(xml);
            } catch (Throwable t) {
                out[0] = new ZaFridaWorkspaceConfig();
            }
        });
        return out[0] != null ? out[0] : new ZaFridaWorkspaceConfig();
    }

    public void saveWorkspace(@NotNull Project project, @NotNull ZaFridaWorkspaceConfig cfg) {
        VirtualFile base = project.getBaseDir();
        if (base == null) return;
        WriteCommandAction.runWriteCommandAction(project, () ->
                SlowOperations.allowSlowOperations(() -> {
                    try {
                        VirtualFile file = base.findChild(ZaFridaProjectFiles.WORKSPACE_FILE);
                        if (file == null) file = base.createChildData(this, ZaFridaProjectFiles.WORKSPACE_FILE);
                        VfsUtil.saveText(file, toWorkspaceXml(cfg));
                    } catch (Throwable ignore) {}
                })
        );
    }

    public @NotNull ZaFridaProjectConfig loadProjectConfig(@NotNull Project project, @NotNull VirtualFile fridaProjectDir) {
        final ZaFridaProjectConfig[] out = new ZaFridaProjectConfig[1];
        SlowOperations.allowSlowOperations(() -> {
            VirtualFile f = fridaProjectDir.findChild(ZaFridaProjectFiles.PROJECT_FILE);
            if (f == null) {
                ZaFridaProjectConfig c = new ZaFridaProjectConfig();
                c.name = fridaProjectDir.getName();
                c.mainScript = ZaFridaProjectFiles.defaultMainScriptName(c.name);
                // platform 由目录路径推断或由 manager 传入覆盖
                out[0] = c;
                return;
            }
            try {
                String xml = VfsUtilCore.loadText(f);
                out[0] = parseProject(xml);
            } catch (Throwable t) {
                ZaFridaProjectConfig c = new ZaFridaProjectConfig();
                c.name = fridaProjectDir.getName();
                c.mainScript = ZaFridaProjectFiles.defaultMainScriptName(c.name);
                out[0] = c;
            }
        });

        if (out[0] != null) return out[0];
        ZaFridaProjectConfig c = new ZaFridaProjectConfig();
        c.name = fridaProjectDir.getName();
        c.mainScript = ZaFridaProjectFiles.defaultMainScriptName(c.name);
        return c;
    }

    public void saveProjectConfig(@NotNull Project project, @NotNull VirtualFile fridaProjectDir, @NotNull ZaFridaProjectConfig cfg) {
        WriteCommandAction.runWriteCommandAction(project, () ->
                SlowOperations.allowSlowOperations(() -> {
                    try {
                        VirtualFile f = fridaProjectDir.findChild(ZaFridaProjectFiles.PROJECT_FILE);
                        if (f == null) f = fridaProjectDir.createChildData(this, ZaFridaProjectFiles.PROJECT_FILE);
                        VfsUtil.saveText(f, toProjectXml(cfg));
                    } catch (Throwable ignore) {}
                })
        );
    }

    public @Nullable String relativize(@NotNull VirtualFile baseDir, @NotNull VirtualFile file) {
        return VfsUtilCore.getRelativePath(file, baseDir, '/');
    }

    // ---------------- XML format ----------------
    private ZaFridaWorkspaceConfig parseWorkspace(String xml) throws Exception {
        Document doc = new SAXBuilder().build(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        Element root = doc.getRootElement();
        ZaFridaWorkspaceConfig cfg = new ZaFridaWorkspaceConfig();
        cfg.lastSelected = root.getAttributeValue("lastSelected");

        for (Element p : root.getChildren("project")) {
            String name = p.getAttributeValue("name");
            String platform = p.getAttributeValue("platform");
            String relDir = p.getAttributeValue("relativeDir");
            if (name == null || platform == null || relDir == null) continue;
            cfg.projects.add(new ZaFridaFridaProject(name, ZaFridaPlatform.valueOf(platform), relDir));
        }
        return cfg;
    }

    private String toWorkspaceXml(ZaFridaWorkspaceConfig cfg) {
        Element root = new Element("zafridaWorkspace");
        root.setAttribute("version", String.valueOf(ZaFridaWorkspaceConfig.VERSION));
        if (cfg.lastSelected != null) root.setAttribute("lastSelected", cfg.lastSelected);

        for (ZaFridaFridaProject p : cfg.projects) {
            Element e = new Element("project");
            e.setAttribute("name", p.getName());
            e.setAttribute("platform", p.getPlatform().name());
            e.setAttribute("relativeDir", p.getRelativeDir());
            root.addContent(e);
        }
        return new XMLOutputter(Format.getPrettyFormat()).outputString(new Document(root));
    }

    private ZaFridaProjectConfig parseProject(String xml) throws Exception {
        Document doc = new SAXBuilder().build(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        Element root = doc.getRootElement();
        ZaFridaProjectConfig cfg = new ZaFridaProjectConfig();
        cfg.name = root.getAttributeValue("name", "");
        cfg.platform = ZaFridaPlatform.valueOf(root.getAttributeValue("platform", "ANDROID"));
        String mainScriptAttr = root.getAttributeValue("mainScript");
        if (mainScriptAttr == null || mainScriptAttr.isBlank()) {
            cfg.mainScript = ZaFridaProjectFiles.defaultMainScriptName(cfg.name);
        } else {
            cfg.mainScript = mainScriptAttr;
        }
        cfg.attachScript = root.getAttributeValue("attachScript", "");
        cfg.lastTarget = root.getAttributeValue("lastTarget");
        cfg.spawnMode = Boolean.parseBoolean(root.getAttributeValue("spawnMode", "true"));
        cfg.extraArgs = root.getAttributeValue("extraArgs", "");
        cfg.targetManual = Boolean.parseBoolean(root.getAttributeValue("targetManual", "true"));
        cfg.processScope = FridaProcessScope.valueOf(
                root.getAttributeValue("processScope", FridaProcessScope.RUNNING_APPS.name())
        );

        String modeRaw = root.getAttributeValue("connectionMode", FridaConnectionMode.USB.name());
        try {
            cfg.connectionMode = FridaConnectionMode.valueOf(modeRaw);
        } catch (IllegalArgumentException ignore) {
            cfg.connectionMode = FridaConnectionMode.USB;
        }

        cfg.remoteHost = root.getAttributeValue("remoteHost", "127.0.0.1");
        cfg.remotePort = parseInt(root.getAttributeValue("remotePort"), 14725);
        cfg.lastDeviceId = root.getAttributeValue("lastDeviceId");
        cfg.lastDeviceHost = root.getAttributeValue("lastDeviceHost");
        return cfg;
    }

    private String toProjectXml(ZaFridaProjectConfig cfg) {
        Element root = new Element("zafridaProject");
        root.setAttribute("version", String.valueOf(ZaFridaProjectConfig.VERSION));
        root.setAttribute("name", cfg.name);
        root.setAttribute("platform", cfg.platform.name());
        root.setAttribute("mainScript", cfg.mainScript);
        root.setAttribute("attachScript", cfg.attachScript == null ? "" : cfg.attachScript);
        root.setAttribute("spawnMode", String.valueOf(cfg.spawnMode));
        root.setAttribute("extraArgs", cfg.extraArgs == null ? "" : cfg.extraArgs);
        if (cfg.lastTarget != null) root.setAttribute("lastTarget", cfg.lastTarget);
        root.setAttribute("targetManual", String.valueOf(cfg.targetManual));
        root.setAttribute("processScope", cfg.processScope.name());
        root.setAttribute("connectionMode", cfg.connectionMode.name());
        root.setAttribute("remoteHost", cfg.remoteHost);
        root.setAttribute("remotePort", String.valueOf(cfg.remotePort));
        if (cfg.lastDeviceId != null) root.setAttribute("lastDeviceId", cfg.lastDeviceId);
        if (cfg.lastDeviceHost != null) root.setAttribute("lastDeviceHost", cfg.lastDeviceHost);
        return new XMLOutputter(Format.getPrettyFormat()).outputString(new Document(root));
    }

    private static int parseInt(@Nullable String value, int fallback) {
        if (value == null || value.isBlank()) return fallback;
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    // 仅在外层已经处于 write-action 时调用
    public void saveWorkspaceNoWriteAction(@NotNull VirtualFile baseDir, @NotNull ZaFridaWorkspaceConfig cfg) {
        SlowOperations.allowSlowOperations(() -> {
            try {
                VirtualFile file = baseDir.findChild(ZaFridaProjectFiles.WORKSPACE_FILE);
                if (file == null) file = baseDir.createChildData(this, ZaFridaProjectFiles.WORKSPACE_FILE);
                VfsUtil.saveText(file, toWorkspaceXml(cfg));
            } catch (Throwable ignore) {}
        });
    }

    // 仅在外层已经处于 write-action 时调用
    public void saveProjectConfigNoWriteAction(@NotNull VirtualFile fridaProjectDir, @NotNull ZaFridaProjectConfig cfg) {
        SlowOperations.allowSlowOperations(() -> {
            try {
                VirtualFile f = fridaProjectDir.findChild(ZaFridaProjectFiles.PROJECT_FILE);
                if (f == null) f = fridaProjectDir.createChildData(this, ZaFridaProjectFiles.PROJECT_FILE);
                VfsUtil.saveText(f, toProjectXml(cfg));
            } catch (Throwable ignore) {}
        });
    }

}
