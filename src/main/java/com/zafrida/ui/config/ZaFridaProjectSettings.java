package com.zafrida.ui.config;

import com.intellij.openapi.components.*;
import com.intellij.openapi.project.Project;
import com.intellij.util.xmlb.XmlSerializerUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;

/**
 * [持久化] IDE 级别的项目配置存储（存储在IntelliJ IDE使用该插件的根目录下）。
 * <p>
 * 注意区分：这是 IntelliJ 原生 Project 的配置，用于存储非共享的用户偏好（如最近打开的包名），
 * 而 {@link com.zafrida.ui.fridaproject.ZaFridaProjectConfig} 是 ZAFrida 自定义的业务项目配置。
 */
@State(
    name = "ZaFridaProjectSettings",
    storages = @Storage("zafrida-project.xml")
)
@Service(Service.Level.PROJECT)
public final class ZaFridaProjectSettings implements PersistentStateComponent<ZaFridaProjectSettings> {

    /** 当前Frida项目 */
    public String packageName = "";
    /** 最近使用的包名列表（按使用时间倒序） */
    public List<String> recentPackages = new ArrayList<>();

    /** 选择的设备ID */
    public String lastSelectedDevice = "";
    /** 连接模式 */
    public DeviceConnectionMode connectionMode = DeviceConnectionMode.USB;

    /** 远程主机地址 */
    public String remoteHost = "127.0.0.1";
    /** 远程连接端口 */
    public int remotePort = 14725;

    /** 附加启动参数 */
    public String additionalArgs = "";
    /** 默认启动模式：true=Spawn, false=Attach, 现在基本已经废弃, 因为分成了Run和Attach两个按钮来控制 */
    public boolean spawnMode = true;

    /**
     * 获取当前项目的 ZaFridaProjectSettings 实例
     * @param project
     * @return ZaFridaProjectSettings
     */
    public static ZaFridaProjectSettings getInstance(@NotNull Project project) {
        return project.getService(ZaFridaProjectSettings.class);
    }

    /**
     * 获取当前状态以进行持久化
     * @return Nullable ZaFridaProjectSettings
     */
    @Override
    public @Nullable ZaFridaProjectSettings getState() {
        return this;
    }

    /**
     * 用于从持久化存储加载状态
     * @param state ZaFridaProjectSettings
     */
    @Override
    public void loadState(@NotNull ZaFridaProjectSettings state) {
        XmlSerializerUtil.copyBean(state, this);
    }

    /**
     * 将指定包名添加到最近使用的包名列表中
     * @param pkg
     */
    public void addRecentPackage(String pkg) {
        if (pkg == null || pkg.trim().isEmpty()) return;
        pkg = pkg.trim();
        recentPackages.remove(pkg);
        recentPackages.add(0, pkg);
        if (recentPackages.size() > 20) {
            recentPackages = new ArrayList<>(recentPackages.subList(0, 20));
        }
    }

    /**
     * 设备连接模式枚举
     */
    public enum DeviceConnectionMode {
        /** USB 连接模式 */
        USB("USB", "-U"),
        /** 远程连接模式 */
        REMOTE("Remote", "-H"),
        /** Gadget 连接模式 */
        GADGET("Gadget", "-H");

        /** 显示名称 */
        private final String displayName;
        /** 对应 frida 命令行参数 */
        private final String fridaFlag;

        /**
         * 构造函数。
         * @param displayName 显示名称
         * @param fridaFlag frida 命令行参数
         */
        DeviceConnectionMode(String displayName, String fridaFlag) {
            this.displayName = displayName;
            this.fridaFlag = fridaFlag;
        }

        /**
         * 获取显示名称。
         * @return 显示名称
         */
        public String getDisplayName() {
            return displayName;
        }

        /**
         * 获取 frida 参数。
         * @return frida 参数
         */
        public String getFridaFlag() {
            return fridaFlag;
        }

        /**
         * 返回显示名称。
         */
        @Override
        public String toString() {
            return displayName;
        }
    }
}
