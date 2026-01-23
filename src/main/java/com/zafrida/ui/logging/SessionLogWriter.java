package com.zafrida.ui.logging;

import org.jetbrains.annotations.NotNull;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
/**
 * [核心组件] 异步日志文件写入器。
 * <p>
 * <strong>设计模式：</strong>
 * 生产者-消费者模式。
 * <ul>
 * <li><strong>生产者：</strong> Frida 进程的 Stdout/Stderr 监听器，调用 {@link #append(String)}。</li>
 * <li><strong>消费者：</strong> 独立的后台守护线程 (Daemon Thread)，负责将队列中的日志刷入磁盘。</li>
 * </ul>
 * <strong>目的：</strong> 避免高频日志输出阻塞 UI 线程或 Frida 进程本身。
 */
public final class SessionLogWriter {

    /** 日志文件路径 */
    private final @NotNull Path file;
    /** 运行状态标志 */
    private final AtomicBoolean running = new AtomicBoolean(true);
    /** 日志消息队列 */
    private final LinkedBlockingQueue<String> queue = new LinkedBlockingQueue<>();
    /** 日志文件写入器 */
    private final BufferedWriter writer;
    /** 后台日志写入线程 */
    private final Thread worker;

    /**
     * 构造函数
     * @param file
     */
    public SessionLogWriter(@NotNull Path file) throws Exception {
        this.file = file;
        this.writer = Files.newBufferedWriter(
                file,
                StandardCharsets.UTF_8,
                StandardOpenOption.APPEND
        );

        this.worker = new Thread(this::runLoop, "ZAFrida-LogWriter");
        this.worker.setDaemon(true);
        this.worker.start();
    }

    /**
     *  后台日志写入循环
     */
    private void runLoop() {
        try {
            while (running.get() || !queue.isEmpty()) {
                String item = queue.poll();
                if (item != null) {
                    writer.write(item);
                    writer.flush();
                } else {
                    try {
                        Thread.sleep(10);
                    } catch (InterruptedException ignored) {
                        // ignore
                        // 忽略中断
                    }
                }
            }
        } catch (Throwable ignored) {
            // ignore
            // 忽略异常
        } finally {
            try {
                writer.flush();
            } catch (Throwable ignored) {
            }
            try {
                writer.close();
            } catch (Throwable ignored) {
            }
        }
    }

    /**
     * 追加日志文本到队列
     * @param text 日志文本
     */
    public void append(@NotNull String text) {
        if (!running.get()) return;
        queue.offer(text);
    }

    /**
     * 关闭日志写入器
     */
    public void close() {
        running.set(false);
        try {
            worker.join(500);
        } catch (InterruptedException ignored) {
        }
    }

    /**
     * 获取日志文件路径
     * @return 日志文件路径
     */
    public @NotNull Path getFile() {
        return file;
    }
}
