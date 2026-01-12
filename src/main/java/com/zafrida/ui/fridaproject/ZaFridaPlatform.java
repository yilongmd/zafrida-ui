package com.zafrida.ui.fridaproject;

public enum ZaFridaPlatform {
    ANDROID, IOS;
    public String rootFolderName() { return this == ANDROID ? "android" : "ios"; }
}
