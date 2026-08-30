package com.zafrida.ui.logging;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SessionLogWriterTest {

    @TempDir
    Path tempDirectory;

    @Test
    void drainsConcurrentAppendsBeforeCloseMarker() throws Exception {
        Path logFile = tempDirectory.resolve("session.log");
        SessionLogWriter writer = new SessionLogWriter(logFile);
        int workers = 4;
        int linesPerWorker = 20;
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(workers);

        for (int worker = 0; worker < workers; worker++) {
            int workerId = worker;
            executor.submit(() -> {
                start.await();
                for (int line = 0; line < linesPerWorker; line++) {
                    writer.append(String.format("%s:%s%n", workerId, line));
                }
                return null;
            });
        }

        start.countDown();
        executor.shutdown();
        assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        writer.close();
        writer.append("after-close\n");

        assertEquals(workers * linesPerWorker,
                Files.readAllLines(logFile, StandardCharsets.UTF_8).size());
    }
}
