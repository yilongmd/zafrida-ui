package com.zafrida.ui.frida;

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
        return String.format("Attach(-p %s)", pid);
    }
}
