package com.zafrida.ui.templates;

public enum ZaFridaTemplateCategory {
    ANDROID("Android"),
    IOS("iOS"),
    CUSTOM("Custom");

    private final String displayName;

    ZaFridaTemplateCategory(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
