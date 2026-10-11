package com.zafrida.ui.util;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public final class ZaFridaNetUtil {

    public static final String LOOPBACK_HOST = "127.0.0.1";
    public static final int DEFAULT_FRIDA_PORT = 14725;
    private static final int MAX_PORT = 65_535;

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

    public static @NotNull String formatHostPort(@NotNull String host, int port) {
        return String.format("%s:%s", host, port);
    }

    /**
     * 解析 {@code host} 或 {@code host:port}；省略端口时使用 fallbackPort。
     * 文本为空、host 为空或端口不在 1-65535 时返回 null。
     */
    public static @Nullable HostPort parseHostPort(@Nullable String text, int fallbackPort) {
        String normalized = normalizeHost(text);
        if (normalized.isEmpty() || containsWhitespace(normalized)) {
            return null;
        }
        int separator = normalized.lastIndexOf(':');
        if (separator < 0) {
            return new HostPort(normalized, fallbackPort);
        }
        String host = normalized.substring(0, separator).trim();
        if (host.isEmpty()) {
            return null;
        }
        int port = parsePort(normalized.substring(separator + 1));
        if (port <= 0) {
            return null;
        }
        return new HostPort(host, port);
    }

    /** 非法或越界时返回 0。 */
    public static int parsePort(@Nullable String portText) {
        if (portText == null || portText.trim().isEmpty()) {
            return 0;
        }
        try {
            int value = Integer.parseInt(portText.trim());
            if (value <= 0 || value > MAX_PORT) {
                return 0;
            }
            return value;
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static boolean containsWhitespace(@NotNull String value) {
        for (int index = 0; index < value.length(); index++) {
            if (Character.isWhitespace(value.charAt(index))) {
                return true;
            }
        }
        return false;
    }

    public static final class HostPort {
        private final @NotNull String host;
        private final int port;

        public HostPort(@NotNull String host, int port) {
            this.host = host;
            this.port = port;
        }

        public @NotNull String getHost() {
            return host;
        }

        public int getPort() {
            return port;
        }

        @Override
        public String toString() {
            return formatHostPort(host, port);
        }
    }
}
