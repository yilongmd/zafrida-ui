package com.zafrida.ui.frida;

import com.zafrida.ui.util.ZaFridaNetUtil;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * 把「连接模式 + 端点」与「选中的真实设备」这两个独立选择解析成一次执行所需的全部参数。
 * 所有需要 Frida 设备参数或 adb serial 的入口都必须经过这里，不得各自从配置里读历史设备。
 */
public final class FridaConnectionPlan {

    private static final String HOST_TYPE_REMOTE = "remote";
    private static final String HOST_NAME_REMOTE = "Remote";
    private static final String HOST_TYPE_GADGET = "gadget";
    private static final String HOST_NAME_GADGET = "Gadget";
    private static final String NO_DEVICE_SELECTED = "No device selected";

    private final @NotNull FridaConnectionMode mode;
    private final @Nullable FridaDevice fridaDevice;
    private final @Nullable String adbSerial;
    private final boolean adbForwardRequired;
    private final int forwardPort;
    private final @Nullable String sessionBlocker;
    private final @Nullable String adbBlocker;

    private FridaConnectionPlan(@NotNull FridaConnectionMode mode,
                                @Nullable FridaDevice fridaDevice,
                                @Nullable String adbSerial,
                                boolean adbForwardRequired,
                                int forwardPort,
                                @Nullable String sessionBlocker,
                                @Nullable String adbBlocker) {
        this.mode = mode;
        this.fridaDevice = fridaDevice;
        this.adbSerial = adbSerial;
        this.adbForwardRequired = adbForwardRequired;
        this.forwardPort = forwardPort;
        this.sessionBlocker = sessionBlocker;
        this.adbBlocker = adbBlocker;
    }

    /**
     * @param selectedDevice    界面上当前选中的真实设备；可能为空，也可能是未连接占位
     * @param adbForwardAllowed 非 Android 项目不走 adb 转发
     */
    public static @NotNull FridaConnectionPlan resolve(@NotNull FridaConnectionMode mode,
                                                       @NotNull String host,
                                                       int port,
                                                       @Nullable FridaDevice selectedDevice,
                                                       boolean adbForwardAllowed) {
        String adbBlocker = null;
        if (selectedDevice != null && !selectedDevice.isConnected()) {
            adbBlocker = String.format("Device %s is not connected. Refresh devices or select another device.", selectedDevice.getId());
        }
        String adbSerial = resolveAdbSerial(selectedDevice);

        if (mode == FridaConnectionMode.USB) {
            if (selectedDevice == null) {
                return new FridaConnectionPlan(mode, null, null, false, 0, NO_DEVICE_SELECTED, null);
            }
            if (adbBlocker != null) {
                return new FridaConnectionPlan(mode, null, null, false, 0, adbBlocker, adbBlocker);
            }
            return new FridaConnectionPlan(mode, selectedDevice, adbSerial, false, 0, null, null);
        }

        FridaDevice hostDevice = createHostDevice(mode, host, port);
        // 没有可用 serial 时仍然转发（不带 -s）：设备列表可能是插入手机之前的旧结果，adb 自己能找到唯一设备。
        boolean forwardRequired = adbForwardAllowed && ZaFridaNetUtil.isLoopbackHost(host);
        if (!forwardRequired) {
            return new FridaConnectionPlan(mode, hostDevice, adbSerial, false, 0, null, adbBlocker);
        }
        return new FridaConnectionPlan(mode, hostDevice, adbSerial, true, port, adbBlocker, adbBlocker);
    }

    public @NotNull FridaConnectionMode getMode() {
        return mode;
    }

    public boolean isGadget() {
        return mode == FridaConnectionMode.GADGET;
    }

    /** 传给 Frida CLI 的设备；存在 {@link #getSessionBlocker()} 时可能为空。 */
    public @Nullable FridaDevice getFridaDevice() {
        return fridaDevice;
    }

    /** 为空表示 adb 不带 {@code -s}，由 adb 自行选择唯一设备。 */
    public @Nullable String getAdbSerial() {
        return adbSerial;
    }

    public boolean isAdbForwardRequired() {
        return adbForwardRequired;
    }

    public int getForwardPort() {
        return forwardPort;
    }

    /** 非空时不得启动 Run/Attach，文案可直接展示给用户。 */
    public @Nullable String getSessionBlocker() {
        return sessionBlocker;
    }

    /** 非空时不得执行 force-stop、open-app、trace 拉取等 adb 操作。 */
    public @Nullable String getAdbBlocker() {
        return adbBlocker;
    }

    public @NotNull String getSummary() {
        if (sessionBlocker != null || fridaDevice == null) {
            if (sessionBlocker != null) {
                return sessionBlocker;
            }
            return NO_DEVICE_SELECTED;
        }
        String fridaPart = String.format("frida %s", String.join(" ", fridaDevice.cliArgs()));
        if (isGadget()) {
            fridaPart = String.format("%s -F", fridaPart);
        }
        if (adbForwardRequired) {
            return String.format("%s → %s", describeForward(), fridaPart);
        }
        if (mode != FridaConnectionMode.USB) {
            return String.format("%s · no adb forward", fridaPart);
        }
        return fridaPart;
    }

    private @NotNull String describeForward() {
        if (adbSerial == null) {
            return String.format("adb forward tcp:%s", forwardPort);
        }
        return String.format("adb -s %s forward tcp:%s", adbSerial, forwardPort);
    }

    private static @Nullable String resolveAdbSerial(@Nullable FridaDevice selectedDevice) {
        if (selectedDevice == null || !selectedDevice.isConnected() || !selectedDevice.isUsb()) {
            return null;
        }
        String id = selectedDevice.getId().trim();
        if (ZaStrUtil.isBlank(id) || FridaDevice.GENERIC_USB_ID.equalsIgnoreCase(id)) {
            return null;
        }
        return id;
    }

    private static @NotNull FridaDevice createHostDevice(@NotNull FridaConnectionMode mode,
                                                         @NotNull String host,
                                                         int port) {
        String hostPort = ZaFridaNetUtil.formatHostPort(host, port);
        String type = HOST_TYPE_REMOTE;
        String name = HOST_NAME_REMOTE;
        if (mode == FridaConnectionMode.GADGET) {
            type = HOST_TYPE_GADGET;
            name = HOST_NAME_GADGET;
        }
        return new FridaDevice(String.format("%s:%s", type, hostPort), type, name, FridaDeviceMode.HOST, hostPort);
    }
}
