package com.zafrida.ui.fridaproject;

import com.intellij.openapi.components.Service;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.text.StringUtil;
import com.intellij.openapi.vfs.VfsUtil;
import com.intellij.openapi.vfs.VfsUtilCore;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.util.SlowOperations;
import com.zafrida.ui.frida.FridaProcessScope;
import com.zafrida.ui.frida.FridaConnectionMode;
import com.intellij.util.messages.Topic;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.util.*;
import java.util.function.Consumer;

/**
 * [项目核心] ZAFrida 自研项目系统管理器。
 * <p>
 * <strong>架构说明：</strong>
 * ZAFrida 引入了轻量级 "子项目" 概念，独立于 IDE 的 Project 结构。
 * <ul>
 * <li><strong>Workspace:</strong> 存储在 {@code zafrida-workspace.xml}，记录项目列表。</li>
 * <li><strong>Project:</strong> 存储在具体目录的 {@code zafrida-project.xml}，记录 App 特有的 Hook 配置。</li>
 * </ul>
 * <p>
 * <strong>职责：</strong> 负责项目的创建、加载、切换激活状态以及配置文件的读写原子性操作。
 */
@Service(Service.Level.PROJECT)
public final class ZaFridaProjectManager {

    public static final Topic<ZaFridaProjectListener> TOPIC =
            Topic.create("ZAFrida.ProjectSelection", ZaFridaProjectListener.class);

    private final Project project;
    private final ZaFridaProjectStorage storage = new ZaFridaProjectStorage();

    private ZaFridaWorkspaceConfig workspace;
    private final Map<String, ZaFridaFridaProject> byName = new LinkedHashMap<>();
    private @Nullable ZaFridaFridaProject active;

    public ZaFridaProjectManager(@NotNull Project project) {
        this.project = project;
        reload();
    }

    public synchronized void reload() {
        workspace = storage.loadWorkspace(project);
        byName.clear();
        for (ZaFridaFridaProject p : workspace.projects) byName.put(p.getName(), p);
        active = workspace.lastSelected != null ? byName.get(workspace.lastSelected) : null;
    }

    public synchronized @NotNull List<ZaFridaFridaProject> listProjects() {
        return new ArrayList<>(byName.values());
    }

    public synchronized @Nullable ZaFridaFridaProject getActiveProject() {
        return active;
    }

    public void setActiveProject(@Nullable ZaFridaFridaProject p) {
        synchronized (this) {
            active = p;
            workspace.lastSelected = p == null ? null : p.getName();
        }
        storage.saveWorkspace(project, workspace);
        project.getMessageBus().syncPublisher(TOPIC).onActiveProjectChanged(p);
    }

    public @NotNull ZaFridaFridaProject createAndActivate(@NotNull String name, @NotNull ZaFridaPlatform platform) {
        String safeName = sanitizeName(name);
        VirtualFile base = project.getBaseDir();
        if (base == null) throw new IllegalStateException("No project base dir");

        String rootFolder = platform.rootFolderName();
        String relDir = rootFolder + "/" + safeName;

        // 先构造对象（不触发写）
        ZaFridaFridaProject fp = new ZaFridaFridaProject(safeName, platform, relDir);

        // 写操作：创建目录、写 project config、写默认脚本、写 workspace 文件
        com.intellij.openapi.command.WriteCommandAction.runWriteCommandAction(project, () -> {
            VirtualFile projectDir = null;
            try {
                projectDir = VfsUtil.createDirectoryIfMissing(base, relDir);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

            // 1) project config
            ZaFridaProjectConfig cfg = new ZaFridaProjectConfig();
            cfg.name = safeName;
            cfg.platform = platform;
            cfg.mainScript = ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT;
            cfg.processScope = FridaProcessScope.RUNNING_APPS;
            cfg.connectionMode = FridaConnectionMode.USB;
            cfg.remoteHost = "127.0.0.1";
            cfg.remotePort = 14725;
            cfg.targetManual = true;

            // 这里不要再内部再套 WriteCommandAction（避免嵌套）
            storage.saveProjectConfigNoWriteAction(projectDir, cfg);

            // 2) default script
            ensureFileNoWriteAction(projectDir, cfg.mainScript, defaultAgentSkeleton());

            // 3) 更新 workspace in-memory + 写 workspace 文件
            synchronized (this) {
                byName.put(fp.getName(), fp);
                workspace.projects.removeIf(x -> x.getName().equals(fp.getName()));
                workspace.projects.add(fp);
                workspace.lastSelected = fp.getName();
                active = fp;
            }
            storage.saveWorkspaceNoWriteAction(base, workspace);

            // refresh vfs
            projectDir.refresh(false, true);
            base.refresh(false, true);
        });

        // 写完后再发事件（避免 UI 在写 action 中做重活）
        project.getMessageBus().syncPublisher(TOPIC).onActiveProjectChanged(fp);
        return fp;
    }


    public @NotNull ZaFridaProjectConfig loadProjectConfig(@NotNull ZaFridaFridaProject p) {
        VirtualFile dir = resolveProjectDir(p);
        if (dir == null) {
            ZaFridaProjectConfig c = new ZaFridaProjectConfig();
            c.name = p.getName();
            c.platform = p.getPlatform();
            return c;
        }
        ZaFridaProjectConfig c = storage.loadProjectConfig(project, dir);
        c.name = p.getName();
        c.platform = p.getPlatform();
        return c;
    }

    public void updateProjectConfig(@NotNull ZaFridaFridaProject p, @NotNull Consumer<ZaFridaProjectConfig> mutator) {
        VirtualFile dir = resolveProjectDir(p);
        if (dir == null) return;
        ZaFridaProjectConfig cfg = storage.loadProjectConfig(project, dir);
        mutator.accept(cfg);
        cfg.name = p.getName();
        cfg.platform = p.getPlatform();
        storage.saveProjectConfig(project, dir, cfg);
    }

    public @Nullable VirtualFile resolveProjectDir(@NotNull ZaFridaFridaProject p) {
        VirtualFile base = project.getBaseDir();
        if (base == null) return null;

        final VirtualFile[] out = new VirtualFile[1];
        SlowOperations.allowSlowOperations(() -> out[0] = base.findFileByRelativePath(p.getRelativeDir()));
        return out[0];
    }

    public @Nullable String toProjectRelativePath(@NotNull ZaFridaFridaProject p, @NotNull VirtualFile file) {
        VirtualFile dir = resolveProjectDir(p);
        if (dir == null) return null;
        return storage.relativize(dir, file);
    }

    private static void ensureFileNoWriteAction(@NotNull VirtualFile dir, @NotNull String name, @NotNull String content) {
        try {
            VirtualFile f = dir.findChild(name);
            if (f == null) {
                f = dir.createChildData(ZaFridaProjectManager.class, name);
                VfsUtil.saveText(f, content);
            }
        } catch (Throwable ignore) {}
    }


    /**
     * 包名末段生成默认主脚本：com.su.fridatest -> fridatest.js
     * 若当前 mainScript 还是默认 agent.js，则升级为该名称（不覆盖用户自定义主脚本）
     */
    public @NotNull VirtualFile ensureMainScriptForTarget(@NotNull ZaFridaFridaProject p, @NotNull String targetId) {
        VirtualFile dir = resolveProjectDir(p);
        if (dir == null) throw new IllegalStateException("Project dir not found");

        ZaFridaProjectConfig cfg = storage.loadProjectConfig(project, dir);
        String oldMain = StringUtil.notNullize(cfg.mainScript, ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT);

        String leaf = targetLeaf(targetId);
        String autoName = leaf + ".js";

        // 仅在仍是默认 agent.js 时自动切换
        if (ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT.equals(oldMain) && !autoName.equals(oldMain)) {
            cfg.mainScript = autoName;
            storage.saveProjectConfig(project, dir, cfg);
            ensureFile(dir, autoName, defaultAgentSkeleton());
            VirtualFile created = dir.findChild(autoName);
            if (created != null) return created;
        }

        ensureFile(dir, cfg.mainScript, defaultAgentSkeleton());
        VirtualFile vf = dir.findChild(cfg.mainScript);
        if (vf != null) return vf;

        // fallback
        ensureFile(dir, ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT, defaultAgentSkeleton());
        return Objects.requireNonNull(dir.findChild(ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT));
    }

    // ---------------- utils ----------------

    private static String sanitizeName(String name) {
        String s = name.trim();
        s = s.replaceAll("[\\\\/:*?\"<>|]", "_");
        if (s.isEmpty()) s = "ZAFridaProject";
        return s;
    }

    private static String targetLeaf(String target) {
        String t = target.trim();
        int idx = t.lastIndexOf('.');
        if (idx >= 0 && idx + 1 < t.length()) return t.substring(idx + 1);
        return t;
    }

    private static void ensureFile(VirtualFile dir, String name, String content) {
        try {
            VirtualFile f = dir.findChild(name);
            if (f == null) {
                f = dir.createChildData(ZaFridaProjectManager.class, name);
                VfsUtil.saveText(f, content);
            }
        } catch (Throwable ignore) {}
    }

    private static String defaultAgentSkeleton() {
        return """
                // ZAFrida default agent
                'use strict';
                console.log('[ZAFrida] agent loaded');
                """;
    }
}
