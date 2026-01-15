package com.zafrida.ui.util;

import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.project.Project;
import org.jetbrains.annotations.NotNull;
/**
 * [工具类] IDE 通知中心封装。
 * <p>
 * <strong>功能：</strong>
 * 向 IDE 右下角发送 "气泡通知" (Balloon Notifications)。
 * 使用 {@code NotificationGroupManager} 获取配置在 plugin.xml 中的 "ZAFrida" 通知组。
 * 替代 {@code Messages.showInfoMessage} 用于非阻塞的信息提示。
 */
public final class ZaFridaNotifier {

    private static final String GROUP_ID = "ZAFrida";

    private ZaFridaNotifier() {
    }

    public static void info(@NotNull Project project, @NotNull String title, @NotNull String content) {
        NotificationGroupManager.getInstance()
                .getNotificationGroup(GROUP_ID)
                .createNotification(title, content, NotificationType.INFORMATION)
                .notify(project);
    }

    public static void warn(@NotNull Project project, @NotNull String title, @NotNull String content) {
        NotificationGroupManager.getInstance()
                .getNotificationGroup(GROUP_ID)
                .createNotification(title, content, NotificationType.WARNING)
                .notify(project);
    }

    public static void error(@NotNull Project project, @NotNull String title, @NotNull String content) {
        NotificationGroupManager.getInstance()
                .getNotificationGroup(GROUP_ID)
                .createNotification(title, content, NotificationType.ERROR)
                .notify(project);
    }
}
