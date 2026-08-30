package com.zafrida.ui.frida;

public enum FridaConnectionMode {
    USB("USB"),
    REMOTE("Remote"),
    GADGET("Gadget");

    private final String displayName;

    FridaConnectionMode(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
