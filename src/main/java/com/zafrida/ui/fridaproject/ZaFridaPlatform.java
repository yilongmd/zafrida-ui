package com.zafrida.ui.fridaproject;
/**
 * [枚举] 支持的目标平台类型。
 * <p>
 * <strong>功能：</strong>
 * 决定项目创建时的默认根目录名称：
 * <ul>
 * <li>{@code ANDROID} -> {@code android/}</li>
 * <li>{@code IOS} -> {@code ios/}</li>
 * </ul>
 * 这种目录隔离有助于在一个 IDE 项目中同时管理双端逆向工程。
 */
public enum ZaFridaPlatform {
    ANDROID, IOS;
    public String rootFolderName() { return this == ANDROID ? "android" : "ios"; }
}
