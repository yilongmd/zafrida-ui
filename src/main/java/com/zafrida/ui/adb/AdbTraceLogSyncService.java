package com.zafrida.ui.adb;

import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.execution.process.CapturingProcessHandler;
import com.intellij.execution.process.ProcessOutput;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.progress.ProcessCanceledException;
import com.intellij.openapi.progress.ProgressIndicator;
import com.intellij.openapi.progress.ProgressManager;
import com.intellij.openapi.progress.Task;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.LocalFileSystem;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Consumer;

public final class AdbTraceLogSyncService {

    private static final Logger LOG = Logger.getInstance(AdbTraceLogSyncService.class);

    private static final int LIST_TIMEOUT_MS = 15_000;
    private static final int PULL_TIMEOUT_MS = 5 * 60_000;
    private static final int STAGING_COPY_TIMEOUT_MS = PULL_TIMEOUT_MS;
    private static final String TRACE_LOGS_SUB_DIR = "trace-logs";
    private static final String REMOTE_PULL_STAGING_DIR = "/sdcard/Download/ZAFrida/trace-logs";

    public void pullAndroidTraceLogsIncrementally(@NotNull Project project,
                                                  @Nullable String deviceId,
                                                  @NotNull String packageName,
                                                  @Nullable String fridaProjectDir,
                                                  @NotNull Consumer<String> info,
                                                  @NotNull Consumer<String> warn,
                                                  @NotNull Consumer<String> error,
                                                  @NotNull Consumer<PullResult> uiOnDone) {
        Objects.requireNonNull(project, "project");
        Objects.requireNonNull(packageName, "packageName");
        Objects.requireNonNull(info, "info");
        Objects.requireNonNull(warn, "warn");
        Objects.requireNonNull(error, "error");
        Objects.requireNonNull(uiOnDone, "uiOnDone");

        String projectBasePath = project.getBasePath();
        if (ZaStrUtil.isBlank(projectBasePath)) {
            uiError(error, "[ZAFrida] Pull Trace Logs failed: project basePath is null");
            ApplicationManager.getApplication().invokeLater(() -> uiOnDone.accept(PullResult.failed("project basePath is null")));
            return;
        }

        String baseDir = projectBasePath;
        if (ZaStrUtil.isNotBlank(fridaProjectDir)) {
            baseDir = fridaProjectDir;
        }

        Path localDir = Paths.get(baseDir).resolve(TRACE_LOGS_SUB_DIR);

        ProgressManager.getInstance().run(new Task.Backgroundable(project, "Pull Trace Logs", true) {
            @Override
            public void run(@NotNull ProgressIndicator indicator) {
                PullResult result;
                try {
                    result = doPullTraceLogs(deviceId, packageName, localDir, indicator, info, warn);
                } catch (ProcessCanceledException canceled) {
                    uiWarn(warn, "[ZAFrida] Pull Trace Logs canceled");
                    result = PullResult.failed("canceled");
                } catch (Throwable t) {
                    String msg = t.getMessage();
                    if (ZaStrUtil.isBlank(msg)) {
                        msg = t.getClass().getName();
                    }
                    uiError(error, String.format("[ZAFrida] Pull Trace Logs failed: %s", msg));
                    result = PullResult.failed(msg);
                }

                PullResult finalResult = result;
                ApplicationManager.getApplication().invokeLater(() -> {
                    if (finalResult.isSuccess() && finalResult.getLocalDir() != null) {
                        LocalFileSystem.getInstance().refreshIoFiles(Collections.singletonList(finalResult.getLocalDir().toFile()), true, true, null);
                    }
                    uiOnDone.accept(finalResult);
                });
            }
        });
    }

    private static @NotNull PullResult doPullTraceLogs(@Nullable String deviceId,
                                                       @NotNull String packageName,
                                                       @NotNull Path localDir,
                                                       @NotNull ProgressIndicator indicator,
                                                       @NotNull Consumer<String> info,
                                                       @NotNull Consumer<String> warn) throws Exception {
        indicator.setIndeterminate(true);

        String remoteDir = String.format("/data/data/%s/files", packageName);
        uiInfo(info, String.format("[ZAFrida] Listing trace logs: %s", remoteDir));

        // 约定：按 mtime 排序（oldest -> newest），这样过滤后的“最后一个”就是最新 trace 文件。
        // 注意：不同 ROM 的 ls 行为可能略有差异，这里提供一次兼容性回退。
        boolean listedByTime = true;
        String listCmd = "ls -ltr " + shQuote(remoteDir);
        AdbCmdOutput listOut = runAdbShellSu(deviceId, listCmd, LIST_TIMEOUT_MS);
        if (listOut.exitCode != 0 && looksLikeUnsupportedLsOption(listOut.stderr)) {
            listedByTime = false;
            uiWarn(warn, "[ZAFrida] ls -t not supported on device, fallback to `ls -l` (name sort).");
            listCmd = "ls -l " + shQuote(remoteDir);
            listOut = runAdbShellSu(deviceId, listCmd, LIST_TIMEOUT_MS);
        }
        if (listOut.exitCode != 0) {
            String detail = firstNonBlank(listOut.stderr, listOut.stdout, "unknown error");
            throw new RuntimeException(String.format("adb list failed (exit=%s): %s (cmd=%s)", listOut.exitCode, detail, listCmd));
        }

        List<RemoteFile> remoteFiles = parseTraceFilesFromLsLong(listOut.stdout);
        if (!listedByTime) {
            remoteFiles.sort(Comparator.comparing(x -> x.name));
        }

        if (remoteFiles.isEmpty()) {
            uiWarn(warn, String.format("[ZAFrida] No trace logs found under: %s", remoteDir));
            return PullResult.success(localDir, 0, 0, 0, null, null);
        }

        Files.createDirectories(localDir);
        indicator.setIndeterminate(false);

        int total = remoteFiles.size();
        String newestName = remoteFiles.get(total - 1).name;
        int downloaded = 0;
        int skipped = 0;

        for (int i = 0; i < total; i++) {
            if (indicator.isCanceled()) {
                throw new ProcessCanceledException();
            }
            double fraction;
            if (total <= 0) {
                fraction = 0.0d;
            } else {
                fraction = (double) i / (double) total;
            }
            indicator.setFraction(fraction);

            RemoteFile rf = remoteFiles.get(i);
            indicator.setText2(rf.name);

            Path localFile = localDir.resolve(rf.name);
            long localSize = safeFileSize(localFile);
            if (localSize >= 0 && localSize == rf.size) {
                skipped++;
                continue;
            }

            String remoteFilePath = remoteDir + "/" + rf.name;
            uiInfo(info, String.format("[ZAFrida] Pulling: %s (remoteSize=%s, localSize=%s)", remoteFilePath, rf.size, localSize));

            downloadViaAdbPull(deviceId, remoteFilePath, localFile, indicator);
            downloaded++;

            long finalSize = safeFileSize(localFile);
            if (finalSize >= 0 && rf.size > 0 && finalSize != rf.size) {
                uiWarn(warn, String.format("[ZAFrida] Size mismatch: %s (expected=%s, actual=%s). The file may be changing on device.", rf.name, rf.size, finalSize));
            }
        }

        indicator.setFraction(1.0d);
        uiInfo(info, String.format("[ZAFrida] Trace logs synced: total=%s, downloaded=%s, skipped=%s, dir=%s",
                total, downloaded, skipped, localDir.toAbsolutePath()));
        Path newestLocalFile = localDir.resolve(newestName);
        return PullResult.success(localDir, total, downloaded, skipped, newestName, newestLocalFile);
    }

    private static boolean looksLikeUnsupportedLsOption(@Nullable String stderr) {
        if (ZaStrUtil.isBlank(stderr)) {
            return false;
        }
        String s = stderr.trim().toLowerCase(Locale.ROOT);
        return s.contains("unknown option")
                || s.contains("illegal option")
                || s.contains("invalid option")
                || s.startsWith("usage:");
    }

    private static void downloadViaAdbPull(@Nullable String deviceId,
                                          @NotNull String remoteFilePath,
                                          @NotNull Path localFile,
                                          @NotNull ProgressIndicator indicator) throws Exception {
        if (indicator.isCanceled()) {
            throw new ProcessCanceledException();
        }

        // 1) staging dir
        AdbCmdOutput mkOut = runAdbShellSu(deviceId, "mkdir -p " + shQuote(REMOTE_PULL_STAGING_DIR), LIST_TIMEOUT_MS);
        if (mkOut.exitCode != 0) {
            String detail = firstNonBlank(mkOut.stderr, mkOut.stdout, "unknown error");
            throw new RuntimeException(String.format("adb mkdir staging failed (exit=%s): %s", mkOut.exitCode, detail));
        }

        String fileName = localFile.getFileName().toString();
        String remoteStagingFile = REMOTE_PULL_STAGING_DIR + "/" + fileName;

        // 2) su copy from /data/data/... to /sdcard/...
        AdbCmdOutput cpOut = runAdbShellSu(deviceId,
                "cp -f " + shQuote(remoteFilePath) + " " + shQuote(remoteStagingFile),
                STAGING_COPY_TIMEOUT_MS);
        if (cpOut.exitCode != 0) {
            String detail = firstNonBlank(cpOut.stderr, cpOut.stdout, "unknown error");
            throw new RuntimeException(String.format("adb staging copy failed (exit=%s): %s", cpOut.exitCode, detail));
        }

        // 3) best-effort chmod (部分设备 /sdcard 下 chmod 行为受限，但 pull 一般仍可读)
        runAdbShellSu(deviceId, "chmod 644 " + shQuote(remoteStagingFile), LIST_TIMEOUT_MS);

        // 4) adb pull
        Files.createDirectories(localFile.getParent());
        AdbCmdOutput pullOut = runAdbPull(deviceId, remoteStagingFile, localFile, PULL_TIMEOUT_MS);
        if (pullOut.exitCode != 0) {
            String detail = firstNonBlank(pullOut.stderr, pullOut.stdout, "unknown error");
            throw new RuntimeException(String.format("adb pull failed (exit=%s): %s", pullOut.exitCode, detail));
        }

        // 5) cleanup (best-effort)
        try {
            runAdbShell(deviceId, "rm -f " + shQuote(remoteStagingFile), LIST_TIMEOUT_MS);
        } catch (Throwable t) {
            LOG.debug(String.format("Cleanup staging file failed: %s", remoteStagingFile), t);
        }
    }

    private static @NotNull AdbCmdOutput runAdbShellSu(@Nullable String deviceId,
                                                       @NotNull String suCommand,
                                                       int timeoutMs) throws Exception {
        List<String> args = baseAdbArgs(deviceId);
        args.add("shell");
        args.add("su");
        args.add("-c");
        args.add(suCommand);
        GeneralCommandLine cmd = new GeneralCommandLine(args).withCharset(StandardCharsets.UTF_8);

        CapturingProcessHandler handler = new CapturingProcessHandler(cmd);
        ProcessOutput out = handler.runProcess(timeoutMs);
        return new AdbCmdOutput(out.getExitCode(), trim(out.getStdout()), trim(out.getStderr()));
    }

    private static @NotNull AdbCmdOutput runAdbShell(@Nullable String deviceId,
                                                     @NotNull String command,
                                                     int timeoutMs) throws Exception {
        List<String> args = baseAdbArgs(deviceId);
        args.add("shell");
        args.add(command);
        GeneralCommandLine cmd = new GeneralCommandLine(args).withCharset(StandardCharsets.UTF_8);

        CapturingProcessHandler handler = new CapturingProcessHandler(cmd);
        ProcessOutput out = handler.runProcess(timeoutMs);
        return new AdbCmdOutput(out.getExitCode(), trim(out.getStdout()), trim(out.getStderr()));
    }

    private static @NotNull AdbCmdOutput runAdbPull(@Nullable String deviceId,
                                                    @NotNull String remoteFilePath,
                                                    @NotNull Path localFile,
                                                    int timeoutMs) throws Exception {
        List<String> args = baseAdbArgs(deviceId);
        args.add("pull");
        args.add(remoteFilePath);
        args.add(localFile.toAbsolutePath().toString());
        GeneralCommandLine cmd = new GeneralCommandLine(args).withCharset(StandardCharsets.UTF_8);

        CapturingProcessHandler handler = new CapturingProcessHandler(cmd);
        ProcessOutput out = handler.runProcess(timeoutMs);
        return new AdbCmdOutput(out.getExitCode(), trim(out.getStdout()), trim(out.getStderr()));
    }

    private static @NotNull List<String> baseAdbArgs(@Nullable String deviceId) {
        List<String> args = new ArrayList<>();
        args.add("adb");
        if (ZaStrUtil.isNotBlank(deviceId)) {
            args.add("-s");
            args.add(deviceId);
        }
        return args;
    }

    private static @NotNull List<RemoteFile> parseTraceFilesFromLsLong(@NotNull String stdout) {
        if (ZaStrUtil.isBlank(stdout)) {
            return new ArrayList<>();
        }

        List<RemoteFile> out = new ArrayList<>();
        String[] lines = stdout.split("\\R");
        for (String line : lines) {
            String trimmed;
            if (line == null) {
                trimmed = "";
            } else {
                trimmed = line.trim();
            }
            if (trimmed.isEmpty()) {
                continue;
            }
            if (trimmed.startsWith("total ")) {
                continue;
            }

            String[] parts = trimmed.split("\\s+");
            if (parts.length < 6) {
                continue;
            }

            // -rw------- 1 u0_a123 u0_a123 1234 2026-02-10 15:42 trace_xxx.txt
            String mode = parts[0];
            if (mode.isEmpty() || mode.charAt(0) != '-') {
                continue;
            }

            long size = parseLong(parts[4], -1L);
            String name = parts[parts.length - 1];

            if (!isTraceLogName(name)) {
                continue;
            }
            if (size < 0) {
                continue;
            }

            out.add(new RemoteFile(name, size));
        }
        return out;
    }

    private static boolean isTraceLogName(@Nullable String name) {
        if (ZaStrUtil.isBlank(name)) {
            return false;
        }
        String lower = name.trim().toLowerCase(Locale.ROOT);
        if (!lower.contains("trace")) {
            return false;
        }
        if (lower.endsWith(".txt")) {
            return true;
        }
        return lower.endsWith(".log");
    }

    private static long parseLong(@NotNull String value, long fallback) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static long safeFileSize(@NotNull Path file) {
        try {
            if (!Files.isRegularFile(file)) {
                return -1L;
            }
            return Files.size(file);
        } catch (Throwable t) {
            LOG.debug(String.format("Read file size failed: %s", file), t);
            return -1L;
        }
    }

    private static @NotNull String shQuote(@NotNull String raw) {
        StringBuilder sb = new StringBuilder(raw.length() + 8);
        sb.append('\'');
        for (int i = 0; i < raw.length(); i++) {
            char ch = raw.charAt(i);
            if (ch == '\'') {
                sb.append("'\"'\"'");
            } else {
                sb.append(ch);
            }
        }
        sb.append('\'');
        return sb.toString();
    }

    private static @NotNull String trim(@Nullable String value) {
        if (value == null) {
            return "";
        }
        return value.trim();
    }

    private static @NotNull String firstNonBlank(@Nullable String a, @Nullable String b, @NotNull String fallback) {
        if (ZaStrUtil.isNotBlank(a)) {
            return a.trim();
        }
        if (ZaStrUtil.isNotBlank(b)) {
            return b.trim();
        }
        return fallback;
    }

    private static void uiInfo(@NotNull Consumer<String> c, @NotNull String message) {
        ApplicationManager.getApplication().invokeLater(() -> c.accept(message));
    }

    private static void uiWarn(@NotNull Consumer<String> c, @NotNull String message) {
        ApplicationManager.getApplication().invokeLater(() -> c.accept(message));
    }

    private static void uiError(@NotNull Consumer<String> c, @NotNull String message) {
        ApplicationManager.getApplication().invokeLater(() -> c.accept(message));
    }

    private static final class AdbCmdOutput {
        private final int exitCode;
        private final @NotNull String stdout;
        private final @NotNull String stderr;

        private AdbCmdOutput(int exitCode, @NotNull String stdout, @NotNull String stderr) {
            this.exitCode = exitCode;
            this.stdout = stdout;
            this.stderr = stderr;
        }
    }

    private static final class RemoteFile {
        private final @NotNull String name;
        private final long size;

        private RemoteFile(@NotNull String name, long size) {
            this.name = name;
            this.size = size;
        }
    }

    public static final class PullResult {
        private final boolean success;
        private final @Nullable Path localDir;
        private final int totalRemoteFiles;
        private final int downloadedFiles;
        private final int skippedFiles;
        private final @Nullable String newestRemoteFileName;
        private final @Nullable Path newestLocalFile;
        private final @Nullable String failureReason;

        private PullResult(boolean success,
                           @Nullable Path localDir,
                           int totalRemoteFiles,
                           int downloadedFiles,
                           int skippedFiles,
                           @Nullable String newestRemoteFileName,
                           @Nullable Path newestLocalFile,
                           @Nullable String failureReason) {
            this.success = success;
            this.localDir = localDir;
            this.totalRemoteFiles = totalRemoteFiles;
            this.downloadedFiles = downloadedFiles;
            this.skippedFiles = skippedFiles;
            this.newestRemoteFileName = newestRemoteFileName;
            this.newestLocalFile = newestLocalFile;
            this.failureReason = failureReason;
        }

        public static @NotNull PullResult success(@NotNull Path localDir,
                                                  int totalRemoteFiles,
                                                  int downloadedFiles,
                                                  int skippedFiles,
                                                  @Nullable String newestRemoteFileName,
                                                  @Nullable Path newestLocalFile) {
            return new PullResult(true, localDir, totalRemoteFiles, downloadedFiles, skippedFiles, newestRemoteFileName, newestLocalFile, null);
        }

        public static @NotNull PullResult failed(@NotNull String reason) {
            return new PullResult(false, null, 0, 0, 0, null, null, reason);
        }

        public boolean isSuccess() {
            return success;
        }

        public @Nullable Path getLocalDir() {
            return localDir;
        }

        public int getTotalRemoteFiles() {
            return totalRemoteFiles;
        }

        public int getDownloadedFiles() {
            return downloadedFiles;
        }

        public int getSkippedFiles() {
            return skippedFiles;
        }

        public @Nullable String getNewestRemoteFileName() {
            return newestRemoteFileName;
        }

        public @Nullable Path getNewestLocalFile() {
            return newestLocalFile;
        }

        public @Nullable String getFailureReason() {
            return failureReason;
        }
    }
}
