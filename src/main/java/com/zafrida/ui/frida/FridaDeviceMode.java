package com.zafrida.ui.frida;
/**
 * [枚举] 设备寻址模式。
 * <p>
 * <strong>用途：</strong>
 * 区分一个 {@link FridaDevice} 是通过物理序列号/ID 寻址（如 ADB Serial / USBMuxd ID），
 * 还是通过 TCP/IP 网络地址寻址。
 */
public enum FridaDeviceMode {
    DEVICE_ID,
    HOST
}
