package com.zafrida.ui.util;

import com.intellij.openapi.util.IconLoader;
import com.zafrida.ui.fridaproject.ZaFridaPlatform;
import org.jetbrains.annotations.Nullable;

import javax.swing.Icon;

public final class ZaFridaIcons {

    private ZaFridaIcons() {
    }

    public static final Icon ANDROID =
            IconLoader.getIcon("/META-INF/icons/platform-android.svg", ZaFridaIcons.class);
    public static final Icon IOS =
            IconLoader.getIcon("/META-INF/icons/platform-ios.svg", ZaFridaIcons.class);
    public static final Icon RUN_FRIDA =
            IconLoader.getIcon("/META-INF/icons/run-frida.svg", ZaFridaIcons.class);
    public static final Icon VSCODE =
            IconLoader.getIcon("/META-INF/icons/vscode.svg", ZaFridaIcons.class);
    public static final Icon EDITOR_010 =
            IconLoader.getIcon("/META-INF/icons/editor-010.png", ZaFridaIcons.class);
    public static final Icon FRIDA_PROJECT =
            IconLoader.getIcon("/META-INF/icons/fridaproject.png", ZaFridaIcons.class);

    public static @Nullable Icon forPlatform(@Nullable ZaFridaPlatform platform) {
        if (platform == null) {
            return null;
        }
        if (platform == ZaFridaPlatform.ANDROID) {
            return ANDROID;
        }
        return IOS;
    }
}
