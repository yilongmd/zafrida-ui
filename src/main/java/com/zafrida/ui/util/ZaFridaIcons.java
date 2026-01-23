package com.zafrida.ui.util;

import com.intellij.openapi.util.IconLoader;
import com.zafrida.ui.fridaproject.ZaFridaPlatform;
import org.jetbrains.annotations.Nullable;

import javax.swing.Icon;

/**
 * [资源] 图标资源加载器。
 */
public final class ZaFridaIcons {

    /**
     * 私有构造函数，禁止实例化。
     */
    private ZaFridaIcons() {
    }

    /** Android 平台图标 */
    public static final Icon ANDROID =
            IconLoader.getIcon("/META-INF/icons/platform-android.svg", ZaFridaIcons.class);
    /** iOS 平台图标 */
    public static final Icon IOS =
            IconLoader.getIcon("/META-INF/icons/platform-ios.svg", ZaFridaIcons.class);
    /** Run 按钮图标 */
    public static final Icon RUN_FRIDA =
            IconLoader.getIcon("/META-INF/icons/run-frida.svg", ZaFridaIcons.class);

    /**
     * 根据平台选择图标。
     * @param platform 平台类型
     * @return 图标或 null
     */
    public static @Nullable Icon forPlatform(@Nullable ZaFridaPlatform platform) {
        if (platform == null) return null;
        return platform == ZaFridaPlatform.ANDROID ? ANDROID : IOS;
    }
}
