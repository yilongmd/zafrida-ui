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

    /** 通知组 ID */
    private static final String GROUP_ID = "ZAFrida";

    /**
     * 私有构造函数，禁止实例化。
     */
    private ZaFridaNotifier() {
    }

    /**
     * 发送信息级通知。
     * @param project 当前 IDE 项目
     * @param title 标题
     * @param content 内容
     */
    public static void info(@NotNull Project project, @NotNull String title, @NotNull String content) {
        NotificationGroupManager.getInstance()
                .getNotificationGroup(GROUP_ID)
                .createNotification(title, content, NotificationType.INFORMATION)
                .notify(project);
    }

    /**
     * 发送警告级通知。
     * @param project 当前 IDE 项目
     * @param title 标题
     * @param content 内容
     */
    public static void warn(@NotNull Project project, @NotNull String title, @NotNull String content) {
        NotificationGroupManager.getInstance()
                .getNotificationGroup(GROUP_ID)
                .createNotification(title, content, NotificationType.WARNING)
                .notify(project);
    }

    /**
     * 发送错误级通知。
     * @param project 当前 IDE 项目
     * @param title 标题
     * @param content 内容
     */
    public static void error(@NotNull Project project, @NotNull String title, @NotNull String content) {
        NotificationGroupManager.getInstance()
                .getNotificationGroup(GROUP_ID)
                .createNotification(title, content, NotificationType.ERROR)
                .notify(project);
    }
}
