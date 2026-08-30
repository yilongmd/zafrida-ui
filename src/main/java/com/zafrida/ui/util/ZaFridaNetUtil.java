package com.zafrida.ui.util;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public final class ZaFridaNetUtil {

    public static final String LOOPBACK_HOST = "127.0.0.1";
    public static final int DEFAULT_FRIDA_PORT = 14725;

    private ZaFridaNetUtil() {
    }

    public static @NotNull String normalizeHost(@Nullable String host) {
        if (host == null) {
            return "";
        }
        return host.trim();
    }

    public static @NotNull String defaultHost(@Nullable String host) {
        return defaultHost(host, LOOPBACK_HOST);
    }

    public static @NotNull String defaultHost(@Nullable String host, @NotNull String fallback) {
        String normalized = normalizeHost(host);
        if (normalized.isEmpty()) {
            return fallback;
        }
        return normalized;
    }

    public static int defaultPort(int port) {
        return defaultPort(port, DEFAULT_FRIDA_PORT);
    }

    public static int defaultPort(int port, int fallback) {
        if (port > 0) {
            return port;
        }
        return fallback;
    }

    public static boolean isLoopbackHost(@Nullable String host) {
        String normalized = normalizeHost(host);
        return LOOPBACK_HOST.equals(normalized) || "localhost".equalsIgnoreCase(normalized);
    }
}
