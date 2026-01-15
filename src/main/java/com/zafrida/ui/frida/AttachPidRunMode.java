package com.zafrida.ui.frida;
/**
 * [运行模式] 按 PID 附加 (Attach by PID)。
 * <p>
 * <strong>映射关系：</strong>
 * 对应 frida 命令行参数 <code>-p &lt;pid&gt;</code>。
 * <p>
 * <strong>场景：</strong>
 * 当用户需要精确控制附加到某个特定进程 ID 时使用（常用于处理多进程应用或同名进程）。
 */
public final class AttachPidRunMode implements FridaRunMode {

    private final int pid;

    public AttachPidRunMode(int pid) {
        this.pid = pid;
    }

    public int getPid() {
        return pid;
    }

    @Override
    public String toString() {
        return "Attach(-p " + pid + ")";
    }
}
