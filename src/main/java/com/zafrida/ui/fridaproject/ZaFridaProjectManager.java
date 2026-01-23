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

    /** 项目切换事件主题 */
    public static final Topic<ZaFridaProjectListener> TOPIC =
            Topic.create("ZAFrida.ProjectSelection", ZaFridaProjectListener.class);

    /** 当前 IntelliJ/PyCharm 项目实例 */
    private final Project project;
    /** 项目存储辅助类(@link ZaFridaProjectStorage) */
    private final ZaFridaProjectStorage storage = new ZaFridaProjectStorage();

    /** 当前工作区配置 */
    private ZaFridaWorkspaceConfig workspace;
    /** 按名称索引的项目映射 */
    private final Map<String, ZaFridaFridaProject> byName = new LinkedHashMap<>();
    /** 当前激活的项目 */
    private @Nullable ZaFridaFridaProject active;

    /**
     * 构造函数，初始化项目管理器并加载工作区配置。
     * @param project
     */
    public ZaFridaProjectManager(@NotNull Project project) {
        this.project = project;
        reload();
    }

    /**
     * 重新加载工作区配置及项目列表。
     * synchronized 确保线程安全。
     */
    public synchronized void reload() {
        workspace = storage.loadWorkspace(project);
        byName.clear();
        for (ZaFridaFridaProject p : workspace.projects) byName.put(p.getName(), p);
        active = workspace.lastSelected != null ? byName.get(workspace.lastSelected) : null;
    }

    /**
     * 列出当前工作区中的所有项目。
     * synchronized 确保线程安全。
     * @return 项目列表
     */
    public synchronized @NotNull List<ZaFridaFridaProject> listProjects() {
        return new ArrayList<>(byName.values());
    }

    /**
     * 获取当前激活的项目。
     * synchronized 确保线程安全。
     * @return 当前激活的项目，若无则返回 null
     */
    public synchronized @Nullable ZaFridaFridaProject getActiveProject() {
        return active;
    }

    /**
     * 根据目录查找对应的项目。
     * @param dir 目标目录
     * @return 对应的项目，若不存在则返回 null
     */
    public @Nullable ZaFridaFridaProject findProjectByDir(@NotNull VirtualFile dir) {
        String rel = toRelativeDir(dir);
        if (rel == null) return null;
        synchronized (this) {
            for (ZaFridaFridaProject p : workspace.projects) {
                if (rel.equals(p.getRelativeDir())) return p;
            }
        }
        return null;
    }

    /**
     * 注册一个已存在的项目目录。
     * @param dir 目标目录
     * @param activate 是否激活该项目
     * @return 注册的项目实例，若目录无效则返回 null
     */
    public @Nullable ZaFridaFridaProject registerExistingProject(@NotNull VirtualFile dir, boolean activate) {
        // 计算相对路径
        String rel = toRelativeDir(dir);
        if (rel == null) return null;

        // 读取项目配置
        ZaFridaProjectConfig cfg = storage.loadProjectConfig(project, dir);
        String name = StringUtil.isEmptyOrSpaces(cfg.name) ? dir.getName() : cfg.name;
        ZaFridaPlatform platform = inferPlatform(rel, cfg.platform);

        ZaFridaFridaProject target = null;
        boolean added = false;
        synchronized (this) {
            for (ZaFridaFridaProject p : workspace.projects) {
                if (rel.equals(p.getRelativeDir())) {
                    target = p;
                    break;
                }
            }
            if (target == null) {
                target = new ZaFridaFridaProject(name, platform, rel);
                byName.put(target.getName(), target);
                ZaFridaFridaProject finalTarget = target;
                workspace.projects.removeIf(x -> x.getName().equals(finalTarget.getName()));
                workspace.projects.add(target);
                added = true;
            }
        }

        // 保存 workspace（若新增且不激活）
        if (added && !activate) {
            storage.saveWorkspace(project, workspace);
        }
        // 激活项目（若需要）
        if (activate && target != null) {
            setActiveProject(target);
        }
        return target;
    }

    /**
     * 设置当前激活的项目。
     * synchronized 确保线程安全。
     * @param p 要激活的项目，若为 null 则表示无激活项目
     */
    public void setActiveProject(@Nullable ZaFridaFridaProject p) {
        synchronized (this) {
            active = p;
            workspace.lastSelected = p == null ? null : p.getName();
        }
        storage.saveWorkspace(project, workspace);
        project.getMessageBus().syncPublisher(TOPIC).onActiveProjectChanged(p);
    }

    /**
     * 创建并激活一个新项目。
     * @param name 项目名称
     * @param platform 目标平台
     * @return 创建并激活的项目实例
     */
    public @NotNull ZaFridaFridaProject createAndActivate(@NotNull String name, @NotNull ZaFridaPlatform platform) {
        // 处理掉名称中的非法字符
        String safeName = sanitizeName(name);
        // 获取IntelliJ/PyCharm IDE使用该插件的项目目录
        VirtualFile base = project.getBaseDir();
        // 确保项目目录存在(这个几乎不可能为空)
        if (base == null) throw new IllegalStateException("No project base dir");

        // 构造相对目录路径
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

            // 1) project config(项目的一些默认配置)
            ZaFridaProjectConfig cfg = new ZaFridaProjectConfig();
            cfg.name = safeName;
            cfg.platform = platform;
            cfg.mainScript = ZaFridaProjectFiles.defaultMainScriptName(safeName);
            cfg.processScope = FridaProcessScope.RUNNING_APPS;
            cfg.connectionMode = FridaConnectionMode.USB;
            cfg.remoteHost = "127.0.0.1";
            cfg.remotePort = 14725;
            cfg.targetManual = true;
            cfg.spawnMode = true;
            cfg.extraArgs = "";

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


    /**
     * 加载指定项目的配置。
     * @param p 目标项目
     * @return NotNull ZaFridaProjectConfig 项目配置实例
     */
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

    /**
     * 更新指定项目的配置。
     * @param p 目标项目
     * @param mutator 用于修改配置的函数
     */
    public void updateProjectConfig(@NotNull ZaFridaFridaProject p, @NotNull Consumer<ZaFridaProjectConfig> mutator) {
        VirtualFile dir = resolveProjectDir(p);
        if (dir == null) return;
        ZaFridaProjectConfig cfg = storage.loadProjectConfig(project, dir);
        mutator.accept(cfg);
        cfg.name = p.getName();
        cfg.platform = p.getPlatform();
        storage.saveProjectConfig(project, dir, cfg);
    }

    /**
    * 解析项目的实际目录。
    * @param p 目标项目
    * @return 对应的虚拟文件目录，若不存在则返回 null
    */
    public @Nullable VirtualFile resolveProjectDir(@NotNull ZaFridaFridaProject p) {
        VirtualFile base = project.getBaseDir();
        if (base == null) return null;

        final VirtualFile[] out = new VirtualFile[1];
        SlowOperations.allowSlowOperations(() -> out[0] = base.findFileByRelativePath(p.getRelativeDir()));
        return out[0];
    }

    /**
     * 将文件路径转换为项目相对路径。
     * @param p 目标项目
     * @param file 目标文件
     * @return 相对路径字符串，若无法解析则返回 null
     */
    public @Nullable String toProjectRelativePath(@NotNull ZaFridaFridaProject p, @NotNull VirtualFile file) {
        VirtualFile dir = resolveProjectDir(p);
        if (dir == null) return null;
        return storage.relativize(dir, file);
    }

    /** 创建文件（无写操作版本）。
     * 这个版本用于在已有写操作的上下文中调用，避免嵌套写操作。
     * @param dir 目标目录
     * @param name 文件名
     * @param content 文件内容
     */
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
        String defaultMain = ZaFridaProjectFiles.defaultMainScriptName(p.getName());
        String oldMain = StringUtil.isEmptyOrSpaces(cfg.mainScript) ? defaultMain : cfg.mainScript;

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

        if (StringUtil.isEmptyOrSpaces(cfg.mainScript)) {
            cfg.mainScript = defaultMain;
            storage.saveProjectConfig(project, dir, cfg);
        }
        ensureFile(dir, cfg.mainScript, defaultAgentSkeleton());
        VirtualFile vf = dir.findChild(cfg.mainScript);
        if (vf != null) return vf;

        // fallback
        ensureFile(dir, defaultMain, defaultAgentSkeleton());
        VirtualFile fallback = dir.findChild(defaultMain);
        if (fallback != null) return fallback;
        ensureFile(dir, ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT, defaultAgentSkeleton());
        return Objects.requireNonNull(dir.findChild(ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT));
    }

    // ---------------- utils ----------------

    /**
     * 清理项目名称，移除非法文件名字符。
     * @param name
     * @return String
     */
    private static String sanitizeName(String name) {
        String s = name.trim();
        s = s.replaceAll("[\\\\/:*?\"<>|]", "_");
        if (s.isEmpty()) s = "ZAFridaProject";
        return s;
    }

    /**
     * 提取目标标识的末段作为脚本命名参考。
     * 例如：com.example.app -> app
     * @param target 目标标识
     * @return 末段字符串
     */
    private static String targetLeaf(String target) {
        String t = target.trim();
        int idx = t.lastIndexOf('.');
        if (idx >= 0 && idx + 1 < t.length()) return t.substring(idx + 1);
        return t;
    }

    /** 创建文件（有写操作版本）。
     * 这个版本会在内部执行写操作。
     * @param dir 目标目录
     * @param name 文件名
     * @param content 文件内容
     */
    private static void ensureFile(VirtualFile dir, String name, String content) {
        try {
            VirtualFile f = dir.findChild(name);
            if (f == null) {
                f = dir.createChildData(ZaFridaProjectManager.class, name);
                VfsUtil.saveText(f, content);
            }
        } catch (Throwable ignore) {}
    }

    /** 将目录转换为相对于项目根目录的路径。
     * @param dir 目标目录
     * @return 相对路径字符串，若无法解析则返回 null
     */
    private @Nullable String toRelativeDir(@NotNull VirtualFile dir) {
        VirtualFile base = project.getBaseDir();
        if (base == null) return null;
        final String[] relRef = new String[1];
        SlowOperations.allowSlowOperations(() -> relRef[0] = VfsUtilCore.getRelativePath(dir, base, '/'));
        if (StringUtil.isEmptyOrSpaces(relRef[0])) return null;
        return relRef[0];
    }

    /** 根据相对目录推断平台类型。
     * @param relativeDir 相对目录
     * @param fallback 回退平台
     * @return 推断的平台类型
     */
    private static @NotNull ZaFridaPlatform inferPlatform(@NotNull String relativeDir, @NotNull ZaFridaPlatform fallback) {
        String rel = relativeDir.replace('\\', '/');
        if (rel.equals("ios") || rel.startsWith("ios/")) return ZaFridaPlatform.IOS;
        if (rel.equals("android") || rel.startsWith("android/")) return ZaFridaPlatform.ANDROID;
        return fallback;
    }

    /** 默认 Agent 脚本骨架。 */
    private static String defaultAgentSkeleton() {
        return """
                // ZAFrida default agent
                'use strict';
                console.log('[ZAFrida] agent loaded');
                """;
    }
}
