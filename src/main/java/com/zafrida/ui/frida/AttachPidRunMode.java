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

    /** 目标进程 PID */
    private final int pid;

    /**
     * 构造函数。
     * @param pid 目标进程 PID
     */
    public AttachPidRunMode(int pid) {
        this.pid = pid;
    }

    /**
     * 获取目标进程 PID。
     * @return PID
     */
    public int getPid() {
        return pid;
    }

    /**
     * 返回该运行模式的字符串表示形式。
     */
    @Override
    public String toString() {
        return "Attach(-p " + pid + ")";
    }
}
