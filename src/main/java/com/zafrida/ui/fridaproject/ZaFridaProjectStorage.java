package com.zafrida.ui.fridaproject;

import com.intellij.openapi.command.WriteCommandAction;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VfsUtil;
import com.intellij.openapi.vfs.VfsUtilCore;
import com.intellij.openapi.vfs.VirtualFile;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.jdom.output.Format;
import org.jdom.output.XMLOutputter;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

public final class ZaFridaProjectStorage {

    public @NotNull ZaFridaWorkspaceConfig loadWorkspace(@NotNull Project project) {
        VirtualFile base = project.getBaseDir();
        if (base == null) return new ZaFridaWorkspaceConfig();
        VirtualFile file = base.findChild(ZaFridaProjectFiles.WORKSPACE_FILE);
        if (file == null) return new ZaFridaWorkspaceConfig();
        try {
            String xml = VfsUtilCore.loadText(file);
            return parseWorkspace(xml);
        } catch (Throwable t) {
            return new ZaFridaWorkspaceConfig();
        }
    }

    public void saveWorkspace(@NotNull Project project, @NotNull ZaFridaWorkspaceConfig cfg) {
        VirtualFile base = project.getBaseDir();
        if (base == null) return;
        WriteCommandAction.runWriteCommandAction(project, () -> {
            try {
                VirtualFile file = base.findChild(ZaFridaProjectFiles.WORKSPACE_FILE);
                if (file == null) file = base.createChildData(this, ZaFridaProjectFiles.WORKSPACE_FILE);
                VfsUtil.saveText(file, toWorkspaceXml(cfg));
            } catch (Throwable ignore) {}
        });
    }

    public @NotNull ZaFridaProjectConfig loadProjectConfig(@NotNull Project project, @NotNull VirtualFile fridaProjectDir) {
        VirtualFile f = fridaProjectDir.findChild(ZaFridaProjectFiles.PROJECT_FILE);
        if (f == null) {
            ZaFridaProjectConfig c = new ZaFridaProjectConfig();
            c.name = fridaProjectDir.getName();
            // platform 由目录路径推断或由 manager 传入覆盖
            return c;
        }
        try {
            String xml = VfsUtilCore.loadText(f);
            return parseProject(xml);
        } catch (Throwable t) {
            ZaFridaProjectConfig c = new ZaFridaProjectConfig();
            c.name = fridaProjectDir.getName();
            return c;
        }
    }

    public void saveProjectConfig(@NotNull Project project, @NotNull VirtualFile fridaProjectDir, @NotNull ZaFridaProjectConfig cfg) {
        WriteCommandAction.runWriteCommandAction(project, () -> {
            try {
                VirtualFile f = fridaProjectDir.findChild(ZaFridaProjectFiles.PROJECT_FILE);
                if (f == null) f = fridaProjectDir.createChildData(this, ZaFridaProjectFiles.PROJECT_FILE);
                VfsUtil.saveText(f, toProjectXml(cfg));
            } catch (Throwable ignore) {}
        });
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
        cfg.mainScript = root.getAttributeValue("mainScript", ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT);
        cfg.lastTarget = root.getAttributeValue("lastTarget");
        return cfg;
    }

    private String toProjectXml(ZaFridaProjectConfig cfg) {
        Element root = new Element("zafridaProject");
        root.setAttribute("version", String.valueOf(ZaFridaProjectConfig.VERSION));
        root.setAttribute("name", cfg.name);
        root.setAttribute("platform", cfg.platform.name());
        root.setAttribute("mainScript", cfg.mainScript);
        if (cfg.lastTarget != null) root.setAttribute("lastTarget", cfg.lastTarget);
        return new XMLOutputter(Format.getPrettyFormat()).outputString(new Document(root));
    }

    // 仅在外层已经处于 write-action 时调用
    public void saveWorkspaceNoWriteAction(@NotNull VirtualFile baseDir, @NotNull ZaFridaWorkspaceConfig cfg) {
        try {
            VirtualFile file = baseDir.findChild(ZaFridaProjectFiles.WORKSPACE_FILE);
            if (file == null) file = baseDir.createChildData(this, ZaFridaProjectFiles.WORKSPACE_FILE);
            VfsUtil.saveText(file, toWorkspaceXml(cfg));
        } catch (Throwable ignore) {}
    }

    // 仅在外层已经处于 write-action 时调用
    public void saveProjectConfigNoWriteAction(@NotNull VirtualFile fridaProjectDir, @NotNull ZaFridaProjectConfig cfg) {
        try {
            VirtualFile f = fridaProjectDir.findChild(ZaFridaProjectFiles.PROJECT_FILE);
            if (f == null) f = fridaProjectDir.createChildData(this, ZaFridaProjectFiles.PROJECT_FILE);
            VfsUtil.saveText(f, toProjectXml(cfg));
        } catch (Throwable ignore) {}
    }

}
