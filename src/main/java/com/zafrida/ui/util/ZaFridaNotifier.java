package com.zafrida.ui.util;

import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.project.Project;
import org.jetbrains.annotations.NotNull;

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
