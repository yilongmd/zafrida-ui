package com.zafrida.ui.fridaproject;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.application.ModalityState;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.project.ProjectUtil;
import com.intellij.openapi.vfs.VfsUtil;
import com.intellij.openapi.vfs.VfsUtilCore;
import com.intellij.openapi.vfs.VirtualFile;
import com.zafrida.ui.frida.FridaProcessScope;
import com.zafrida.ui.frida.FridaConnectionMode;
import com.zafrida.ui.util.ZaStrUtil;
import com.intellij.util.messages.Topic;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.util.*;
import java.util.function.Consumer;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public final class ZaFridaProjectManager {

    private static final Logger LOG = Logger.getInstance(ZaFridaProjectManager.class);

    public static final Topic<ZaFridaProjectListener> TOPIC =
            Topic.create("ZAFrida.ProjectSelection", ZaFridaProjectListener.class);

    private final Project project;
    private final ZaFridaProjectStorage storage = new ZaFridaProjectStorage();
    private final ConfigTaskQueue configTaskQueue;

    private ZaFridaWorkspaceConfig workspace;
    private final Map<String, ZaFridaFridaProject> byName = new LinkedHashMap<>();
    private @Nullable ZaFridaFridaProject active;
    // 与 active 在同一同步块更新，命令构建时无需临时读取 XML。
    private @NotNull String activePythonEnvironmentPath = "";

    public ZaFridaProjectManager(@NotNull Project project) {
        this.project = project;
        this.configTaskQueue = new ConfigTaskQueue(project);
        this.workspace = new ZaFridaWorkspaceConfig();
        reloadAsync(null);
    }

    public void reloadAsync(@Nullable Runnable uiAfter) {
        AtomicReference<ZaFridaFridaProject> activeRef = new AtomicReference<>();
        runConfigTask(() -> {
            ZaFridaWorkspaceConfig loaded = storage.loadWorkspace(project);
            Map<String, ZaFridaFridaProject> loadedByName = new LinkedHashMap<>();
            for (ZaFridaFridaProject p : loaded.projects) {
                loadedByName.put(p.getName(), p);
            }
            ZaFridaFridaProject loadedActive = null;
            if (loaded.lastSelected != null) {
                loadedActive = loadedByName.get(loaded.lastSelected);
            }
            String loadedPythonEnvironmentPath = loadPythonEnvironmentPathInternal(loadedActive);
            synchronized (this) {
                workspace = loaded;
                byName.clear();
                byName.putAll(loadedByName);
                active = loadedActive;
                activePythonEnvironmentPath = loadedPythonEnvironmentPath;
            }
            activeRef.set(loadedActive);
        }, () -> {
            project.getMessageBus().syncPublisher(TOPIC).onActiveProjectChanged(activeRef.get());
            if (uiAfter != null) {
                uiAfter.run();
            }
        }, null);
    }

    public synchronized @NotNull List<ZaFridaFridaProject> listProjects() {
        return new ArrayList<>(byName.values());
    }

    public void listPythonEnvironmentPathsAsync(@NotNull Consumer<List<String>> uiConsumer,
                                                @Nullable ModalityState modality) {
        AtomicReference<List<String>> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(listPythonEnvironmentPathsInternal()),
                () -> uiConsumer.accept(ref.get()),
                modality);
    }

    public synchronized @Nullable ZaFridaFridaProject getActiveProject() {
        return active;
    }

    public synchronized @NotNull String getActivePythonEnvironmentPath() {
        return activePythonEnvironmentPath;
    }

    public void findProjectByDirAsync(@NotNull VirtualFile dir, @NotNull Consumer<ZaFridaFridaProject> uiConsumer) {
        AtomicReference<ZaFridaFridaProject> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(findProjectByDirInternal(dir)), () -> uiConsumer.accept(ref.get()), null);
    }

    private @Nullable ZaFridaFridaProject findProjectByDirInternal(@NotNull VirtualFile dir) {
        String rel = toRelativeDirInternal(dir);
        if (rel == null) {
            return null;
        }
        synchronized (this) {
            for (ZaFridaFridaProject p : workspace.projects) {
                if (rel.equals(p.getRelativeDir())) {
                    return p;
                }
            }
        }
        return null;
    }

    public void registerExistingProjectAsync(@NotNull VirtualFile dir,
                                             boolean activate,
                                             @NotNull Consumer<ZaFridaFridaProject> uiConsumer) {
        AtomicReference<ZaFridaFridaProject> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(registerExistingProjectInternal(dir, activate)), () -> {
            ZaFridaFridaProject result = ref.get();
            if (activate && result != null) {
                project.getMessageBus().syncPublisher(TOPIC).onActiveProjectChanged(result);
            }
            uiConsumer.accept(result);
        }, null);
    }

    private @Nullable ZaFridaFridaProject registerExistingProjectInternal(@NotNull VirtualFile dir, boolean activate) {
        String rel = toRelativeDirInternal(dir);
        if (rel == null) {
            return null;
        }

        ZaFridaProjectConfig cfg = storage.loadProjectConfig(project, dir);
        String name;
        if (ZaStrUtil.isBlank(cfg.name)) {
            name = dir.getName();
        } else {
            name = cfg.name;
        }
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
                ZaFridaFridaProject sameName = byName.get(name);
                if (sameName != null) {
                    LOG.warn(String.format(
                            "Cannot register ZAFrida project '%s' from %s; the name is already used by %s",
                            name,
                            rel,
                            sameName.getRelativeDir()
                    ));
                    return null;
                }
                target = new ZaFridaFridaProject(name, platform, rel);
                byName.put(target.getName(), target);
                ZaFridaFridaProject finalTarget = target;
                workspace.projects.removeIf(x -> x.getName().equals(finalTarget.getName()));
                workspace.projects.add(target);
                added = true;
            }
        }

        if (added && !activate) {
            storage.saveWorkspace(project, workspace);
        }
        if (activate && target != null) {
            setActiveProjectInternal(target);
        }
        return target;
    }

    public void setActiveProjectAsync(@Nullable ZaFridaFridaProject p) {
        setActiveProjectAsync(p, null);
    }

    public void setActiveProjectAsync(@Nullable ZaFridaFridaProject p, @Nullable Runnable uiAfter) {
        AtomicReference<ZaFridaFridaProject> ref = new AtomicReference<>(p);
        runConfigTask(() -> setActiveProjectInternal(ref.get()), () -> {
            project.getMessageBus().syncPublisher(TOPIC).onActiveProjectChanged(ref.get());
            if (uiAfter != null) {
                uiAfter.run();
            }
        }, null);
    }

    private void setActiveProjectInternal(@Nullable ZaFridaFridaProject p) {
        String pythonEnvironmentPath = loadPythonEnvironmentPathInternal(p);
        synchronized (this) {
            active = p;
            activePythonEnvironmentPath = pythonEnvironmentPath;
            if (p == null) {
                workspace.lastSelected = null;
            } else {
                workspace.lastSelected = p.getName();
            }
        }
        storage.saveWorkspace(project, workspace);
    }

    public void createAndActivateAsync(@NotNull String name,
                                       @NotNull ZaFridaPlatform platform,
                                       @NotNull Consumer<ZaFridaFridaProject> uiConsumer,
                                       @NotNull Consumer<Throwable> errorConsumer) {
        AtomicReference<ZaFridaFridaProject> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(createAndActivateInternal(name, platform)), () -> {
            ZaFridaFridaProject created = ref.get();
            if (created == null) {
                errorConsumer.accept(new IllegalStateException("Create project failed"));
                return;
            }
            project.getMessageBus().syncPublisher(TOPIC).onActiveProjectChanged(created);
            uiConsumer.accept(created);
        }, null, errorConsumer);
    }

    private @NotNull ZaFridaFridaProject createAndActivateInternal(@NotNull String name, @NotNull ZaFridaPlatform platform) {
        String safeName = sanitizeName(name);
        VirtualFile base = ProjectUtil.guessProjectDir(project);
        if (base == null) {
            throw new IllegalStateException("No project base dir");
        }

        String rootFolder = platform.rootFolderName();
        String relDir = String.format("%s/%s", rootFolder, safeName);

        synchronized (this) {
            if (byName.containsKey(safeName)) {
                throw new IllegalStateException(String.format("ZAFrida project already exists: %s", safeName));
            }
        }
        VirtualFile existingDirectory = base.findFileByRelativePath(relDir);
        if (existingDirectory != null) {
            throw new IllegalStateException(String.format("Project directory already exists: %s", existingDirectory.getPath()));
        }

        ZaFridaFridaProject fp = new ZaFridaFridaProject(safeName, platform, relDir);

        com.intellij.openapi.command.WriteCommandAction.runWriteCommandAction(project, () -> {
            VirtualFile projectDir = null;
            try {
                projectDir = VfsUtil.createDirectoryIfMissing(base, relDir);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

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

            // 当前已持有 write action，以下存储方法不得再次嵌套写操作。
            storage.saveProjectConfigNoWriteAction(projectDir, cfg);

            ensureFileNoWriteAction(projectDir, cfg.mainScript, defaultAgentSkeleton());

            synchronized (this) {
                byName.put(fp.getName(), fp);
                workspace.projects.removeIf(x -> x.getName().equals(fp.getName()));
                workspace.projects.add(fp);
                workspace.lastSelected = fp.getName();
                active = fp;
                activePythonEnvironmentPath = "";
            }
            storage.saveWorkspaceNoWriteAction(base, workspace);

            projectDir.refresh(false, true);
            base.refresh(false, true);
        });

        return fp;
    }


    public void loadProjectConfigAsync(@NotNull ZaFridaFridaProject p,
                                       @NotNull Consumer<ZaFridaProjectConfig> uiConsumer) {
        loadProjectConfigAsync(p, uiConsumer, null);
    }

    public void loadProjectConfigAsync(@NotNull ZaFridaFridaProject p,
                                       @NotNull Consumer<ZaFridaProjectConfig> uiConsumer,
                                       @Nullable ModalityState modality) {
        AtomicReference<ZaFridaProjectConfig> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(loadProjectConfigInternal(p)), () -> uiConsumer.accept(ref.get()), modality);
    }

    public void loadProjectUiStateAsync(@NotNull ZaFridaFridaProject p,
                                        @NotNull Consumer<ProjectUiState> uiConsumer) {
        loadProjectUiStateAsync(p, uiConsumer, null);
    }

    public void loadProjectUiStateAsync(@NotNull ZaFridaFridaProject p,
                                        @NotNull Consumer<ProjectUiState> uiConsumer,
                                        @Nullable ModalityState modality) {
        AtomicReference<ProjectUiState> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(loadProjectUiStateInternal(p)), () -> uiConsumer.accept(ref.get()), modality);
    }

    public void updateProjectConfigAsync(@NotNull ZaFridaFridaProject p,
                                         @NotNull Consumer<ZaFridaProjectConfig> mutator) {
        updateProjectConfigAsync(p, mutator, null);
    }

    public void updateProjectConfigAsync(@NotNull ZaFridaFridaProject p,
                                         @NotNull Consumer<ZaFridaProjectConfig> mutator,
                                         @Nullable Runnable uiAfter) {
        runConfigTask(() -> updateProjectConfigInternal(p, mutator), uiAfter, null);
    }

    public void updateProjectConfigAsync(@NotNull ZaFridaFridaProject p,
                                         @NotNull Consumer<ZaFridaProjectConfig> mutator,
                                         @Nullable Runnable uiAfter,
                                         @NotNull Consumer<Throwable> errorConsumer) {
        runConfigTask(() -> updateProjectConfigInternal(p, mutator), uiAfter, null, errorConsumer);
    }

    public void updateMainScriptPathAsync(@NotNull ZaFridaFridaProject p, @NotNull VirtualFile file) {
        updateProjectConfigAsync(p, cfg -> {
            String rel = toProjectRelativePathInternal(p, file);
            if (ZaStrUtil.isNotBlank(rel)) {
                cfg.mainScript = rel;
            }
        });
    }

    public void updateAttachScriptPathAsync(@NotNull ZaFridaFridaProject p, @NotNull VirtualFile file) {
        updateProjectConfigAsync(p, cfg -> {
            String rel = toProjectRelativePathInternal(p, file);
            if (ZaStrUtil.isNotBlank(rel)) {
                cfg.attachScript = rel;
            }
        });
    }

    public void resolveRunScriptFileAsync(@NotNull ZaFridaFridaProject p,
                                          @NotNull String targetId,
                                          boolean gadgetMode,
                                          @NotNull Consumer<VirtualFile> uiConsumer) {
        AtomicReference<VirtualFile> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(resolveRunScriptFileInternal(p, targetId, gadgetMode)),
                () -> uiConsumer.accept(ref.get()),
                null);
    }

    public void resolveAttachScriptFileAsync(@NotNull ZaFridaFridaProject p,
                                             @NotNull Consumer<VirtualFile> uiConsumer) {
        AtomicReference<VirtualFile> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(resolveAttachScriptFileInternal(p)), () -> uiConsumer.accept(ref.get()), null);
    }

    public void ensureMainScriptForTargetAsync(@NotNull ZaFridaFridaProject p,
                                               @NotNull String targetId,
                                               @NotNull Consumer<VirtualFile> uiConsumer) {
        AtomicReference<VirtualFile> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(ensureMainScriptForTargetInternal(p, targetId)),
                () -> uiConsumer.accept(ref.get()),
                null);
    }

    public void ensureDefaultMainScriptAsync(@NotNull ZaFridaFridaProject p, @Nullable Runnable uiAfter) {
        runConfigTask(() -> ensureDefaultMainScriptInternal(p), uiAfter, null);
    }

    public void resolveProjectDirAsync(@NotNull ZaFridaFridaProject p, @NotNull Consumer<VirtualFile> uiConsumer) {
        AtomicReference<VirtualFile> ref = new AtomicReference<>();
        runConfigTask(() -> ref.set(resolveProjectDirInternal(p)), () -> uiConsumer.accept(ref.get()), null);
    }

    public static final class ProjectUiState {
        private final @NotNull ZaFridaProjectConfig config;
        private final @Nullable VirtualFile projectDir;
        private final @Nullable VirtualFile mainScriptFile;
        private final @Nullable VirtualFile attachScriptFile;

        private ProjectUiState(@NotNull ZaFridaProjectConfig config,
                               @Nullable VirtualFile projectDir,
                               @Nullable VirtualFile mainScriptFile,
                               @Nullable VirtualFile attachScriptFile) {
            this.config = config;
            this.projectDir = projectDir;
            this.mainScriptFile = mainScriptFile;
            this.attachScriptFile = attachScriptFile;
        }

        public @NotNull ZaFridaProjectConfig getConfig() {
            return config;
        }

        public @Nullable VirtualFile getProjectDir() {
            return projectDir;
        }

        public @Nullable VirtualFile getMainScriptFile() {
            return mainScriptFile;
        }

        public @Nullable VirtualFile getAttachScriptFile() {
            return attachScriptFile;
        }
    }

    private @NotNull ZaFridaProjectConfig loadProjectConfigInternal(@NotNull ZaFridaFridaProject p) {
        VirtualFile dir = resolveProjectDirInternal(p);
        if (dir == null) {
            ZaFridaProjectConfig c = new ZaFridaProjectConfig();
            c.name = p.getName();
            c.platform = p.getPlatform();
            return c;
        }
        ZaFridaProjectConfig c = storage.loadProjectConfig(project, dir);
        c.name = p.getName();
        c.platform = p.getPlatform();
        updateCachedPythonEnvironmentPath(p, c.pythonEnvironmentPath);
        return c;
    }

    private ProjectUiState loadProjectUiStateInternal(@NotNull ZaFridaFridaProject p) {
        ZaFridaProjectConfig cfg = loadProjectConfigInternal(p);
        VirtualFile dir = resolveProjectDirInternal(p);
        VirtualFile mainScript = null;
        VirtualFile attachScript = null;
        if (dir != null) {
            if (ZaStrUtil.isNotBlank(cfg.mainScript)) {
                VirtualFile cand = dir.findFileByRelativePath(cfg.mainScript);
                if (cand != null && !cand.isDirectory()) {
                    mainScript = cand;
                }
            }
            if (ZaStrUtil.isNotBlank(cfg.attachScript)) {
                VirtualFile cand = dir.findFileByRelativePath(cfg.attachScript);
                if (cand != null && !cand.isDirectory()) {
                    attachScript = cand;
                }
            }
        }
        return new ProjectUiState(cfg, dir, mainScript, attachScript);
    }

    private void updateProjectConfigInternal(@NotNull ZaFridaFridaProject p,
                                             @NotNull Consumer<ZaFridaProjectConfig> mutator) {
        VirtualFile dir = resolveProjectDirInternal(p);
        if (dir == null) {
            return;
        }
        ZaFridaProjectConfig cfg = storage.loadProjectConfig(project, dir);
        mutator.accept(cfg);
        cfg.name = p.getName();
        cfg.platform = p.getPlatform();
        storage.saveProjectConfig(project, dir, cfg);
        updateCachedPythonEnvironmentPath(p, cfg.pythonEnvironmentPath);
    }

    private @NotNull String loadPythonEnvironmentPathInternal(@Nullable ZaFridaFridaProject fridaProject) {
        if (fridaProject == null) {
            return "";
        }
        VirtualFile dir = resolveProjectDirInternal(fridaProject);
        if (dir == null) {
            return "";
        }
        ZaFridaProjectConfig config = storage.loadProjectConfig(project, dir);
        return normalizePythonEnvironmentPath(config.pythonEnvironmentPath);
    }

    private @NotNull List<String> listPythonEnvironmentPathsInternal() {
        LinkedHashSet<String> paths = new LinkedHashSet<>();
        List<ZaFridaFridaProject> projects = listProjects();
        for (ZaFridaFridaProject fridaProject : projects) {
            VirtualFile dir = resolveProjectDirInternal(fridaProject);
            if (dir == null) {
                continue;
            }
            ZaFridaProjectConfig config = storage.loadProjectConfig(project, dir);
            String path = normalizePythonEnvironmentPath(config.pythonEnvironmentPath);
            if (!path.isEmpty()) {
                paths.add(path);
            }
        }
        return new ArrayList<>(paths);
    }

    private void updateCachedPythonEnvironmentPath(@NotNull ZaFridaFridaProject fridaProject,
                                                   @Nullable String pythonEnvironmentPath) {
        synchronized (this) {
            if (fridaProject.equals(active)) {
                activePythonEnvironmentPath = normalizePythonEnvironmentPath(pythonEnvironmentPath);
            }
        }
    }

    private static @NotNull String normalizePythonEnvironmentPath(@Nullable String path) {
        if (ZaStrUtil.isBlank(path)) {
            return "";
        }
        return path.trim();
    }

    private @Nullable VirtualFile resolveProjectDirInternal(@NotNull ZaFridaFridaProject p) {
        VirtualFile base = ProjectUtil.guessProjectDir(project);
        if (base == null) {
            return null;
        }
        return base.findFileByRelativePath(p.getRelativeDir());
    }

    private @Nullable String toProjectRelativePathInternal(@NotNull ZaFridaFridaProject p, @NotNull VirtualFile file) {
        VirtualFile dir = resolveProjectDirInternal(p);
        if (dir == null) {
            return null;
        }
        return storage.relativize(dir, file);
    }

    private @Nullable VirtualFile resolveRunScriptFileInternal(@NotNull ZaFridaFridaProject p,
                                                               @NotNull String targetId,
                                                               boolean gadgetMode) {
        VirtualFile dir = resolveProjectDirInternal(p);
        if (dir == null) {
            return null;
        }
        ZaFridaProjectConfig cfg = storage.loadProjectConfig(project, dir);
        if (ZaStrUtil.isNotBlank(cfg.mainScript)) {
            VirtualFile cand = dir.findFileByRelativePath(cfg.mainScript);
            if (cand != null && !cand.isDirectory()) {
                return cand;
            }
        }
        if (gadgetMode) {
            return null;
        }
        return ensureMainScriptForTargetInternal(p, targetId);
    }

    private @Nullable VirtualFile resolveAttachScriptFileInternal(@NotNull ZaFridaFridaProject p) {
        VirtualFile dir = resolveProjectDirInternal(p);
        if (dir == null) {
            return null;
        }
        ZaFridaProjectConfig cfg = storage.loadProjectConfig(project, dir);
        if (ZaStrUtil.isBlank(cfg.attachScript)) {
            return null;
        }
        VirtualFile cand = dir.findFileByRelativePath(cfg.attachScript);
        if (cand != null && !cand.isDirectory()) {
            return cand;
        }
        return null;
    }

    private void ensureDefaultMainScriptInternal(@NotNull ZaFridaFridaProject p) {
        VirtualFile dir = resolveProjectDirInternal(p);
        if (dir == null) {
            return;
        }
        ZaFridaProjectConfig cfg = loadProjectConfigInternal(p);
        if (hasValidMainScriptInternal(dir, cfg)) {
            return;
        }
        String picked = pickDefaultMainScriptInternal(dir);
        String updated;
        if (picked == null) {
            updated = "";
        } else {
            updated = picked;
        }
        if (!updated.equals(cfg.mainScript)) {
            cfg.mainScript = updated;
            storage.saveProjectConfig(project, dir, cfg);
        }
    }

    private boolean hasValidMainScriptInternal(@NotNull VirtualFile dir, @NotNull ZaFridaProjectConfig cfg) {
        if (ZaStrUtil.isBlank(cfg.mainScript)) {
            return false;
        }
        VirtualFile cand = dir.findFileByRelativePath(cfg.mainScript);
        return cand != null && !cand.isDirectory();
    }

    private @Nullable String pickDefaultMainScriptInternal(@NotNull VirtualFile dir) {
        String sameName = ZaFridaProjectFiles.defaultMainScriptName(dir.getName());
        VirtualFile match = dir.findChild(sameName);
        if (match != null && !match.isDirectory()) {
            return sameName;
        }

        VirtualFile agent = dir.findChild(ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT);
        if (agent != null && !agent.isDirectory()) {
            return ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT;
        }

        VirtualFile[] children = dir.getChildren();
        if (children == null || children.length == 0) {
            return null;
        }

        Arrays.sort(children, Comparator.comparing(VirtualFile::getName, String.CASE_INSENSITIVE_ORDER));
        for (VirtualFile child : children) {
            if (!child.isDirectory()
                    && ("js".equalsIgnoreCase(child.getExtension()) || "ts".equalsIgnoreCase(child.getExtension()))) {
                return child.getName();
            }
        }
        return null;
    }

    private void runConfigTask(@NotNull Runnable ioTask,
                               @Nullable Runnable uiTask,
                               @Nullable ModalityState modality) {
        runConfigTask(ioTask, uiTask, modality, null);
    }

    private void runConfigTask(@NotNull Runnable ioTask,
                               @Nullable Runnable uiTask,
                               @Nullable ModalityState modality,
                               @Nullable Consumer<Throwable> errorConsumer) {
        configTaskQueue.submit(() -> {
            try {
                ioTask.run();
            } catch (Throwable t) {
                LOG.warn("ZAFrida project configuration task failed", t);
                if (errorConsumer != null) {
                    ApplicationManager.getApplication().invokeLater(() -> {
                        if (!project.isDisposed()) {
                            errorConsumer.accept(t);
                        }
                    }, ModalityState.nonModal());
                }
                return;
            }
            if (uiTask == null) {
                return;
            }
            ModalityState state;
            if (modality != null) {
                state = modality;
            } else {
                state = ModalityState.nonModal();
            }
            ApplicationManager.getApplication().invokeLater(() -> {
                if (!project.isDisposed()) {
                    uiTask.run();
                }
            }, state);
        });
    }

    /** 原子状态只允许一个 worker，保证配置读改写按提交顺序串行执行。 */
    private static final class ConfigTaskQueue {
        private final Project project;
        private final AtomicBoolean running = new AtomicBoolean(false);
        private final ConcurrentLinkedQueue<Runnable> queue = new ConcurrentLinkedQueue<>();

        private ConfigTaskQueue(@NotNull Project project) {
            this.project = project;
        }

        private void submit(@NotNull Runnable task) {
            queue.add(task);
            trySchedule();
        }

        private void trySchedule() {
            if (!running.compareAndSet(false, true)) {
                return;
            }
            scheduleNext();
        }

        private void scheduleNext() {
            Runnable next = queue.poll();
            if (next == null) {
                running.set(false);
                if (!queue.isEmpty()) {
                    trySchedule();
                }
                return;
            }
            ApplicationManager.getApplication().executeOnPooledThread(() -> {
                try {
                    if (!project.isDisposed()) {
                        next.run();
                    }
                } finally {
                    scheduleNext();
                }
            });
        }
    }

    private static void ensureFileNoWriteAction(@NotNull VirtualFile dir, @NotNull String name, @NotNull String content) {
        try {
            VirtualFile f = dir.findChild(name);
            if (f == null) {
                f = dir.createChildData(ZaFridaProjectManager.class, name);
                VfsUtil.saveText(f, content);
            }
        } catch (IOException e) {
            throw new IllegalStateException(String.format("Create ZAFrida script failed: %s/%s", dir.getPath(), name), e);
        }
    }


    private @NotNull VirtualFile ensureMainScriptForTargetInternal(@NotNull ZaFridaFridaProject p,
                                                                   @NotNull String targetId) {
        VirtualFile dir = resolveProjectDirInternal(p);
        if (dir == null) {
            throw new IllegalStateException("Project dir not found");
        }

        ZaFridaProjectConfig cfg = storage.loadProjectConfig(project, dir);
        String defaultMain = ZaFridaProjectFiles.defaultMainScriptName(p.getName());
        String oldMain;
        if (ZaStrUtil.isBlank(cfg.mainScript)) {
            oldMain = defaultMain;
        } else {
            oldMain = cfg.mainScript;
        }

        String leaf = targetLeaf(targetId);
        String autoName = String.format("%s.js", leaf);

        // 仅在仍是默认 agent.js 时自动切换
        if (ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT.equals(oldMain) && !autoName.equals(oldMain)) {
            cfg.mainScript = autoName;
            storage.saveProjectConfig(project, dir, cfg);
            ensureFile(dir, autoName, defaultAgentSkeleton());
            VirtualFile created = dir.findChild(autoName);
            if (created != null) {
                return created;
            }
        }

        if (ZaStrUtil.isBlank(cfg.mainScript)) {
            cfg.mainScript = defaultMain;
            storage.saveProjectConfig(project, dir, cfg);
        }
        ensureFile(dir, cfg.mainScript, defaultAgentSkeleton());
        VirtualFile vf = dir.findChild(cfg.mainScript);
        if (vf != null) {
            return vf;
        }

        ensureFile(dir, defaultMain, defaultAgentSkeleton());
        VirtualFile fallback = dir.findChild(defaultMain);
        if (fallback != null) {
            return fallback;
        }
        ensureFile(dir, ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT, defaultAgentSkeleton());
        return Objects.requireNonNull(dir.findChild(ZaFridaProjectFiles.DEFAULT_MAIN_SCRIPT));
    }

    private static String sanitizeName(String name) {
        String s = name.trim();
        if (".".equals(s) || "..".equals(s)) {
            throw new IllegalArgumentException("ZAFrida project name cannot be '.' or '..'");
        }
        s = s.replaceAll("[\\\\/:*?\"<>|]", "_");
        if (s.isEmpty()) {
            s = "ZAFridaProject";
        }
        return s;
    }

    private static String targetLeaf(String target) {
        String t = target.trim();
        int idx = t.lastIndexOf('.');
        if (idx >= 0 && idx + 1 < t.length()) {
            return t.substring(idx + 1);
        }
        return t;
    }

    private static void ensureFile(VirtualFile dir, String name, String content) {
        try {
            VirtualFile f = dir.findChild(name);
            if (f == null) {
                f = dir.createChildData(ZaFridaProjectManager.class, name);
                VfsUtil.saveText(f, content);
            }
        } catch (IOException e) {
            throw new IllegalStateException(String.format("Create ZAFrida script failed: %s/%s", dir.getPath(), name), e);
        }
    }

    private @Nullable String toRelativeDirInternal(@NotNull VirtualFile dir) {
        VirtualFile base = ProjectUtil.guessProjectDir(project);
        if (base == null) {
            return null;
        }
        String rel = VfsUtilCore.getRelativePath(dir, base, '/');
        if (ZaStrUtil.isBlank(rel)) {
            return null;
        }
        return rel;
    }

    private static @NotNull ZaFridaPlatform inferPlatform(@NotNull String relativeDir, @NotNull ZaFridaPlatform fallback) {
        String rel = relativeDir.replace('\\', '/');
        if (rel.equals("ios") || rel.startsWith("ios/")) {
            return ZaFridaPlatform.IOS;
        }
        if (rel.equals("android") || rel.startsWith("android/")) {
            return ZaFridaPlatform.ANDROID;
        }
        return fallback;
    }

    private static String defaultAgentSkeleton() {
        return """
                // ZAFrida default agent
                'use strict';
                console.log('[ZAFrida] agent loaded');
                """;
    }
}
