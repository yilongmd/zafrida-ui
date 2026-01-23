package com.zafrida.ui.frida;
/**
 * [枚举] 进程列表查询作用域 (frida-ps 过滤器)。
 * <p>
 * 决定调用 <code>frida-ps</code> 时使用哪些参数：
 * <ul>
 * <li>{@link #RUNNING_PROCESSES}: 列出所有运行中进程 (无额外参数)。</li>
 * <li>{@link #RUNNING_APPS}: 仅列出有界面的运行中 App (对应参数 <code>-a</code>)。</li>
 * <li>{@link #INSTALLED_APPS}: 列出所有已安装的应用，包括未运行的 (对应参数 <code>-a -i</code>)。</li>
 * </ul>
 */
public enum FridaProcessScope {
    /** 所有运行中进程 */
    RUNNING_PROCESSES,
    /** 运行中的前台应用 */
    RUNNING_APPS,
    /** 已安装应用（含未运行） */
    INSTALLED_APPS
}
