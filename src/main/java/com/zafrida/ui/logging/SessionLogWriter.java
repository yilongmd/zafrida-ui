package com.zafrida.ui.logging;

import com.intellij.openapi.diagnostic.Logger;
import org.jetbrains.annotations.NotNull;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/** append 可由进程输出线程并发调用；单一后台线程负责按序写盘和关闭 writer。 */
public final class SessionLogWriter {

    private static final Logger LOG = Logger.getInstance(SessionLogWriter.class);
    private static final int MAX_PENDING_CHUNKS = 16_384;
    private static final int MAX_BATCH_SIZE = 256;
    private static final long POLL_TIMEOUT_MS = 250L;

    private final @NotNull Path file;
    private final AtomicBoolean accepting = new AtomicBoolean(true);
    private final AtomicLong droppedChunks = new AtomicLong();
    private final LinkedBlockingQueue<String> queue = new LinkedBlockingQueue<>(MAX_PENDING_CHUNKS);
    private final BufferedWriter writer;
    private final Thread worker;

    public SessionLogWriter(@NotNull Path file) throws Exception {
        this.file = file;
        this.writer = Files.newBufferedWriter(
                file,
                StandardCharsets.UTF_8,
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND
        );

        this.worker = new Thread(this::runLoop, String.format("ZAFrida-LogWriter-%s", file.getFileName()));
        this.worker.setDaemon(true);
        this.worker.start();
    }

    private void runLoop() {
        try {
            List<String> batch = new ArrayList<>(MAX_BATCH_SIZE);
            while (accepting.get() || !queue.isEmpty()) {
                String first = queue.poll(POLL_TIMEOUT_MS, TimeUnit.MILLISECONDS);
                if (first == null) {
                    continue;
                }
                batch.add(first);
                queue.drainTo(batch, MAX_BATCH_SIZE - 1);
                writeDroppedChunkNotice();
                for (String item : batch) {
                    writer.write(item);
                }
                batch.clear();
                writer.flush();
            }
            writeDroppedChunkNotice();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.warn(String.format("Session log writer interrupted: %s", file), e);
        } catch (IOException e) {
            LOG.warn(String.format("Write session log failed: %s", file), e);
        } finally {
            try {
                writer.flush();
            } catch (IOException e) {
                LOG.warn(String.format("Flush session log failed: %s", file), e);
            }
            try {
                writer.close();
            } catch (IOException e) {
                LOG.warn(String.format("Close session log failed: %s", file), e);
            }
        }
    }

    public synchronized void append(@NotNull String text) {
        if (!accepting.get()) {
            return;
        }
        if (!queue.offer(text)) {
            droppedChunks.incrementAndGet();
        }
    }

    public synchronized void close() {
        if (!accepting.compareAndSet(true, false)) {
            return;
        }
        try {
            worker.join(1_000);
            if (worker.isAlive()) {
                LOG.warn(String.format("Timed out waiting for session log writer: %s", file));
                worker.interrupt();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.warn(String.format("Interrupted while closing session log writer: %s", file), e);
        }
    }

    public @NotNull Path getFile() {
        return file;
    }

    private void writeDroppedChunkNotice() throws IOException {
        long count = droppedChunks.getAndSet(0L);
        if (count <= 0L) {
            return;
        }
        writer.write(String.format("%n[ZAFrida] Log writer dropped %s output chunks because the disk queue was full.%n", count));
    }
}
