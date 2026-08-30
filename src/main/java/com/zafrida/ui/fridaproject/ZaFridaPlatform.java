package com.zafrida.ui.fridaproject;

public enum ZaFridaPlatform {
    ANDROID,
    IOS;

    public String rootFolderName() {
        if (this == ANDROID) {
            return "android";
        }
        return "ios";
    }
}
