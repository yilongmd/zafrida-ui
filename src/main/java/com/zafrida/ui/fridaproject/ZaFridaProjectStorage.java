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

    /**
     * 加载工作区配置。
     * @param project 当前 IDE 项目
     * @return 工作区配置
     */
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

    /**
     * 保存工作区配置。
     * @param project 当前 IDE 项目
     * @param cfg 工作区配置
     */
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

    /**
     * 加载指定 Frida 项目的配置。
     * @param project 当前 IDE 项目
     * @param fridaProjectDir Frida 项目目录
     * @return 项目配置
     */
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

    /**
     * 保存指定 Frida 项目的配置。
     * @param project 当前 IDE 项目
     * @param fridaProjectDir Frida 项目目录
     * @param cfg 项目配置
     */
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

    /**
     * 计算相对路径。
     * @param baseDir 基准目录
     * @param file 目标文件
     * @return 相对路径或 null
     */
    public @Nullable String relativize(@NotNull VirtualFile baseDir, @NotNull VirtualFile file) {
        return VfsUtilCore.getRelativePath(file, baseDir, '/');
    }

    // ---------------- XML format ----------------
    // ---------------- XML 格式 ----------------
    /**
     * 解析工作区 XML。
     * @param xml XML 内容
     * @return 工作区配置
     */
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

    /**
     * 序列化工作区配置为 XML。
     * @param cfg 工作区配置
     * @return XML 字符串
     */
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

    /**
     * 解析项目 XML。
     * @param xml XML 内容
     * @return 项目配置
     */
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

    /**
     * 序列化项目配置为 XML。
     * @param cfg 项目配置
     * @return XML 字符串
     */
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

    /**
     * 安全解析整数。
     * @param value 字符串值
     * @param fallback 解析失败时的回退值
     * @return 解析结果
     */
    private static int parseInt(@Nullable String value, int fallback) {
        if (value == null || value.isBlank()) return fallback;
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    // 仅在外层已经处于 write-action 时调用
    /**
     * 在已处于写操作上下文时保存工作区配置。
     * @param baseDir 项目根目录
     * @param cfg 工作区配置
     */
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
    /**
     * 在已处于写操作上下文时保存项目配置。
     * @param fridaProjectDir Frida 项目目录
     * @param cfg 项目配置
     */
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
