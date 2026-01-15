package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
/**
 * [数据模型] 单个进程或应用信息实体。
 * <p>
 * <strong>数据来源：</strong> 解析 <code>frida-ps</code> 命令的行输出。
 * <p>
 * <strong>字段说明：</strong>
 * <ul>
 * <li>{@code pid}: 进程 ID。<strong>注意：</strong> 当 {@link FridaProcessScope#INSTALLED_APPS} 模式下列出未运行应用时，此字段为 {@code null}。</li>
 * <li>{@code name}: 进程显示名称（如 "WhatsApp"）。</li>
 * <li>{@code identifier}: 包名或 Bundle ID（如 "com.whatsapp"）。</li>
 * </ul>
 */
public final class FridaProcess {

    private final @Nullable Integer pid;
    private final @NotNull String name;
    private final @Nullable String identifier;

    public FridaProcess(@Nullable Integer pid, @NotNull String name, @Nullable String identifier) {
        this.pid = pid;
        this.name = name;
        this.identifier = identifier;
    }

    public @Nullable Integer getPid() {
        return pid;
    }

    public @NotNull String getName() {
        return name;
    }

    public @Nullable String getIdentifier() {
        return identifier;
    }
}
