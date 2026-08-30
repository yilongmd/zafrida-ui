package com.zafrida.ui.ui;

import com.intellij.icons.AllIcons;
import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.LocalFileSystem;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.util.ui.JBUI;
import com.intellij.util.ui.UIUtil;
import com.zafrida.ui.adb.AdbTraceLogSyncService;
import com.zafrida.ui.fridaproject.ZaFridaFridaProject;
import com.zafrida.ui.fridaproject.ZaFridaPlatform;
import com.zafrida.ui.fridaproject.ZaFridaProjectConfig;
import com.zafrida.ui.fridaproject.ZaFridaProjectListener;
import com.zafrida.ui.fridaproject.ZaFridaProjectManager;
import com.zafrida.ui.util.ProjectFileUtil;
import com.zafrida.ui.util.ZaFrida010EditorUtil;
import com.zafrida.ui.util.ZaFridaIcons;
import com.zafrida.ui.util.ZaFridaNotifier;
import com.zafrida.ui.util.ZaFridaTextUtil;
import com.zafrida.ui.util.ZaFridaVsCodeUtil;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public final class ZaFridaToolsPanel extends JPanel implements Disposable {

    private static final Logger LOG = Logger.getInstance(ZaFridaToolsPanel.class);

    private final @NotNull Project project;
    private final @NotNull ZaFridaConsoleTabsPanel consoleTabsPanel;
    private final @NotNull ZaFridaConsolePanel runConsolePanel;
    private final @NotNull ZaFridaProjectManager fridaProjectManager;

    private final JLabel platformIconLabel = new JLabel();
    private final JLabel platformTextLabel = new JLabel("-", SwingConstants.LEFT);

    private final JButton pullTraceLogsBtn = new JButton("Pull Logs");
    private final JLabel traceLastFileLabel = new JLabel("(not pulled)");
    private final JButton locateTraceFileBtn = new JButton("");
    private final JButton openTraceInVsCodeBtn = new JButton("");
    private final JButton openTraceIn010EditorBtn = new JButton("");

    private @Nullable Path lastTraceLocalFile;

    public ZaFridaToolsPanel(@NotNull Project project, @NotNull ZaFridaConsoleTabsPanel consoleTabsPanel) {
        super(new BorderLayout());
        this.project = project;
        this.consoleTabsPanel = consoleTabsPanel;
        this.runConsolePanel = consoleTabsPanel.getRunConsolePanel();
        this.fridaProjectManager = project.getService(ZaFridaProjectManager.class);

        setBorder(JBUI.Borders.empty());

        JPanel form = new JPanel(new GridBagLayout());

        int row = 0;
        row = addRow(form, row, new JLabel("Platform"), buildPlatformRow());
        row = addRow(form, row, new JLabel("Trace"), buildTraceRow());

        add(form, BorderLayout.NORTH);

        subscribeToFridaProjectChanges();
        applyActiveProjectToUi(fridaProjectManager.getActiveProject());
        bindActions();
    }

    private void bindActions() {
        pullTraceLogsBtn.addActionListener(e -> triggerPullTraceLogs());
        locateTraceFileBtn.addActionListener(e -> locateLastTraceFile());
        openTraceInVsCodeBtn.addActionListener(e -> openLastTraceFileInVsCode());
        openTraceIn010EditorBtn.addActionListener(e -> openLastTraceFileIn010Editor());
    }

    private JPanel buildPlatformRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        platformIconLabel.setToolTipText("Project platform");
        platformTextLabel.setToolTipText("Project platform");
        p.add(platformIconLabel);
        p.add(platformTextLabel);
        return p;
    }

    private JPanel buildTraceRow() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        pullTraceLogsBtn.setIcon(AllIcons.Actions.MenuSaveall);
        pullTraceLogsBtn.setToolTipText("Pull /data/data/<package>/files/*trace*.txt|.log to <fridaProject>/trace-logs (incremental by size)");

        traceLastFileLabel.setForeground(UIUtil.getContextHelpForeground());
        traceLastFileLabel.setToolTipText("Last trace log file");

        locateTraceFileBtn.setIcon(AllIcons.General.Locate);
        locateTraceFileBtn.setToolTipText("Locate last trace log in Project View");
        tuneIconButton(locateTraceFileBtn);
        locateTraceFileBtn.setEnabled(false);

        openTraceInVsCodeBtn.setIcon(ZaFridaIcons.VSCODE);
        openTraceInVsCodeBtn.setToolTipText("Open last trace log in VS Code");
        tuneIconButton(openTraceInVsCodeBtn);
        openTraceInVsCodeBtn.setEnabled(false);

        openTraceIn010EditorBtn.setIcon(ZaFridaIcons.EDITOR_010);
        openTraceIn010EditorBtn.setToolTipText("Open last trace log in 010 Editor");
        tuneIconButton(openTraceIn010EditorBtn);
        openTraceIn010EditorBtn.setEnabled(false);

        p.add(pullTraceLogsBtn);
        p.add(traceLastFileLabel);
        p.add(locateTraceFileBtn);
        p.add(openTraceInVsCodeBtn);
        p.add(openTraceIn010EditorBtn);
        return p;
    }

    private int addRow(@NotNull JPanel form, int row, @NotNull JLabel label, @NotNull JPanel field) {
        GridBagConstraints labelC = new GridBagConstraints();
        labelC.gridx = 0;
        labelC.gridy = row;
        labelC.weightx = 0;
        labelC.anchor = GridBagConstraints.EAST;
        labelC.insets = new Insets(6, 8, 6, 8);

        GridBagConstraints fieldC = new GridBagConstraints();
        fieldC.gridx = 1;
        fieldC.gridy = row;
        fieldC.weightx = 1;
        fieldC.fill = GridBagConstraints.HORIZONTAL;
        fieldC.insets = new Insets(6, 0, 6, 8);

        form.add(label, labelC);
        form.add(field, fieldC);
        return row + 1;
    }

    private void subscribeToFridaProjectChanges() {
        project.getMessageBus().connect(this).subscribe(ZaFridaProjectManager.TOPIC, new ZaFridaProjectListener() {
            @Override
            public void onActiveProjectChanged(@Nullable ZaFridaFridaProject newProject) {
                ApplicationManager.getApplication().invokeLater(() -> applyActiveProjectToUi(newProject));
            }
        });
    }

    private void applyActiveProjectToUi(@Nullable ZaFridaFridaProject active) {
        if (active == null) {
            platformIconLabel.setIcon(null);
            platformTextLabel.setText("-");
            platformTextLabel.setToolTipText("No active project");
            resetTraceUi();
            return;
        }
        platformIconLabel.setIcon(ZaFridaIcons.forPlatform(active.getPlatform()));
        platformTextLabel.setText(active.getPlatform().name());
        platformTextLabel.setToolTipText(String.format("Platform: %s", active.getPlatform().name()));

        resetTraceUi();
    }

    private void triggerPullTraceLogs() {
        ZaFridaFridaProject active = fridaProjectManager.getActiveProject();
        if (active == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Pull Trace Logs requires an active ZAFrida project");
            return;
        }
        if (active.getPlatform() != ZaFridaPlatform.ANDROID) {
            ZaFridaNotifier.warn(project, "ZAFrida", "Pull Trace Logs currently supports Android projects only");
            return;
        }

        pullTraceLogsBtn.setEnabled(false);
        locateTraceFileBtn.setEnabled(false);
        openTraceInVsCodeBtn.setEnabled(false);
        consoleTabsPanel.showRunConsole();

        fridaProjectManager.loadProjectConfigAsync(active, cfg -> {
            if (project.isDisposed()) {
                pullTraceLogsBtn.setEnabled(true);
                return;
            }

            String packageName = resolveAndroidPackageName(cfg);
            if (ZaStrUtil.isBlank(packageName)) {
                pullTraceLogsBtn.setEnabled(true);
                ZaFridaNotifier.warn(project, "ZAFrida", "Pull Trace Logs requires an Android package name (Target)");
                runConsolePanel.warn("[ZAFrida] Pull Trace Logs requires an Android package name (Target).");
                return;
            }

            String deviceId = normalizeAdbDeviceId(cfg.lastDeviceId);
            String fridaProjectDir = resolveActiveFridaProjectDir(active);

            AdbTraceLogSyncService svc = ApplicationManager.getApplication().getService(AdbTraceLogSyncService.class);
            svc.pullAndroidTraceLogsIncrementally(
                    project,
                    deviceId,
                    packageName,
                    fridaProjectDir,
                    runConsolePanel::info,
                    runConsolePanel::warn,
                    runConsolePanel::error,
                    result -> {
                        pullTraceLogsBtn.setEnabled(true);
                        if (!result.isSuccess()) {
                            ZaFridaNotifier.error(project, "ZAFrida", String.format("Pull Trace Logs failed: %s", result.getFailureReason()));
                            return;
                        }
                        applyTraceSyncResultToUi(result);
                        String dir = "";
                        if (result.getLocalDir() != null) {
                            dir = result.getLocalDir().toAbsolutePath().toString();
                        }
                        ZaFridaNotifier.info(
                                project,
                                "ZAFrida",
                                String.format("Trace logs synced: total=%s, downloaded=%s, skipped=%s (%s)",
                                        result.getTotalRemoteFiles(),
                                        result.getDownloadedFiles(),
                                        result.getSkippedFiles(),
                                        dir
                                )
                        );
                    }
            );
        });
    }

    private void applyTraceSyncResultToUi(@NotNull AdbTraceLogSyncService.PullResult result) {
        String newestName = result.getNewestRemoteFileName();
        Path newestLocal = result.getNewestLocalFile();
        if (ZaStrUtil.isBlank(newestName) || newestLocal == null) {
            traceLastFileLabel.setText("(no trace log)");
            traceLastFileLabel.setToolTipText("No trace log");
            lastTraceLocalFile = null;
            locateTraceFileBtn.setEnabled(false);
            openTraceInVsCodeBtn.setEnabled(false);
            return;
        }

        traceLastFileLabel.setText(newestName);
        traceLastFileLabel.setToolTipText(newestLocal.toAbsolutePath().toString());
        lastTraceLocalFile = newestLocal;

        boolean exists = Files.isRegularFile(newestLocal);
        locateTraceFileBtn.setEnabled(exists);
        openTraceInVsCodeBtn.setEnabled(exists);
        openTraceIn010EditorBtn.setEnabled(exists);
    }

    private void resetTraceUi() {
        traceLastFileLabel.setText("(not pulled)");
        traceLastFileLabel.setToolTipText("Last trace log file");
        lastTraceLocalFile = null;
        locateTraceFileBtn.setEnabled(false);
        openTraceInVsCodeBtn.setEnabled(false);
        openTraceIn010EditorBtn.setEnabled(false);
    }

    private void locateLastTraceFile() {
        Path file = lastTraceLocalFile;
        if (file == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "No trace log yet");
            return;
        }
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            File ioFile = file.toFile();
            VirtualFile vf = LocalFileSystem.getInstance().refreshAndFindFileByIoFile(ioFile);
            if (vf != null && vf.isValid() && !vf.isDirectory()) {
                ApplicationManager.getApplication().invokeLater(() -> ProjectFileUtil.openAndSelectLogFileReadOnly(project, vf));
                return;
            }

            File parent = ioFile.getParentFile();
            if (parent != null) {
                VirtualFile dir = LocalFileSystem.getInstance().refreshAndFindFileByIoFile(parent);
                if (dir != null && dir.isValid()) {
                    ApplicationManager.getApplication().invokeLater(() -> {
                        ProjectFileUtil.openAndSelectInProject(project, dir);
                        ZaFridaNotifier.warn(project, "ZAFrida", String.format("Trace log not found, located directory: %s", parent.getAbsolutePath()));
                    });
                    return;
                }
            }

            ApplicationManager.getApplication().invokeLater(() ->
                    ZaFridaNotifier.warn(project, "ZAFrida", String.format("Trace log not found: %s", ioFile.getAbsolutePath())));
        });
    }

    private void openLastTraceFileInVsCode() {
        Path file = lastTraceLocalFile;
        if (file == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "No trace log yet");
            return;
        }
        ZaFridaVsCodeUtil.openFileInVsCodeAsync(project, file.toAbsolutePath().toString());
    }

    private void openLastTraceFileIn010Editor() {
        Path file = lastTraceLocalFile;
        if (file == null) {
            ZaFridaNotifier.warn(project, "ZAFrida", "No trace log yet");
            return;
        }
        ZaFrida010EditorUtil.openFileIn010EditorAsync(project, file.toAbsolutePath().toString());
    }

    private static void tuneIconButton(@NotNull JButton btn) {
        btn.setBorderPainted(false);
        btn.setContentAreaFilled(false);
        btn.setFocusPainted(false);
        btn.setOpaque(false);
        btn.setMargin(new Insets(0, 0, 0, 0));
        btn.setPreferredSize(new Dimension(18, 18));
    }

    private @Nullable String resolveActiveFridaProjectDir(@NotNull ZaFridaFridaProject active) {
        String basePath = project.getBasePath();
        if (ZaStrUtil.isBlank(basePath)) {
            return null;
        }
        Path dir = Paths.get(basePath, active.getRelativeDir());
        try {
            if (Files.isDirectory(dir)) {
                return dir.toAbsolutePath().toString();
            }
        } catch (Throwable t) {
            LOG.debug(String.format("Resolve Frida project dir failed: %s", dir), t);
        }
        return basePath;
    }

    private static @Nullable String resolveAndroidPackageName(@NotNull ZaFridaProjectConfig cfg) {
        String target = cfg.lastTarget;
        if (ZaStrUtil.isBlank(target)) {
            return null;
        }
        String trimmed = target.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        if (ZaFridaTextUtil.isNumeric(trimmed)) {
            return null;
        }
        return trimmed;
    }

    private static @Nullable String normalizeAdbDeviceId(@Nullable String lastDeviceId) {
        if (ZaStrUtil.isBlank(lastDeviceId)) {
            return null;
        }
        String trimmed = lastDeviceId.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        if ("usb".equalsIgnoreCase(trimmed)) {
            return null;
        }
        return trimmed;
    }

    @Override
    public void dispose() {
        // MessageBus 连接绑定到 this，由 Disposer 自动释放。
    }
}
