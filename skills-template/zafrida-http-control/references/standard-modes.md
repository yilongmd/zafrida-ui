# USB 与 Remote 标准模式

USB 和 Remote 使用标准 frida-server 生命周期，不需要 Gadget 的 force-stop → open-app → 等待注入流程。除非当前项目本身有额外初始化要求，否则不要加入固定 sleep，也不要默认调用 `adb-open-app`。

开始前先读取 `state`，确认活动项目、Python/Frida 环境、连接模式、Target 和脚本。只修改用户要求或当前操作缺失的字段。修改命令返回 `accepted: true` 后，仍须通过 `wait-session` 和日志判断结果。

## 共同规则

- Run 使用 Target 启动目标并加载 Run Script；当前实现对应 Frida spawn。
- Attach 是可选操作，只在目标进程已经运行且当前任务确实需要时执行。
- 不要为了“保险”同时执行 Run 和 Attach；根据任务选择一种，或按项目明确流程组合。
- 同类型会话已经运行而任务要求重启时，先执行对应 stop，再等待 `stopped`；没有运行时不要多余 stop。
- 启动后用 `wait-session --state running`，不要用固定 sleep 判断成功。
- 会话立即回到 `stopped` 时，先读日志；不能盲目重放 Run/Attach。
- Frida 客户端与设备端 frida-server 版本应兼容；不确定时运行 `python-env-test` 和 `diagnostics`。

## USB 模式

USB 模式直接连接 Frida 枚举出的 USB 设备。只有一个通用 USB 设备时 CLI 使用 `-U`；选中具体设备 ID 时使用 `-D <id>`。多设备场景必须显式选择 ID，不能依赖列表顺序。

### 标准 Run

```bash
python3 <skill-dir>/scripts/zafrida_api.py state
python3 <skill-dir>/scripts/zafrida_api.py mode-set --mode usb
python3 <skill-dir>/scripts/zafrida_api.py wait-device --type usb --timeout 60 --interval 2
python3 <skill-dir>/scripts/zafrida_api.py devices
python3 <skill-dir>/scripts/zafrida_api.py device-select --id <device-id>
python3 <skill-dir>/scripts/zafrida_api.py processes --scope apps
python3 <skill-dir>/scripts/zafrida_api.py target-set --target <spawn-target>
python3 <skill-dir>/scripts/zafrida_api.py run-script-set --path /absolute/agent.js
python3 <skill-dir>/scripts/zafrida_api.py run
python3 <skill-dir>/scripts/zafrida_api.py wait-session --type run --state running --timeout 15 --interval 0.5
python3 <skill-dir>/scripts/zafrida_api.py run-log-tail --max-bytes 65536
```

如果项目已经处于 USB 模式并选中了正确设备，不要重复执行 `mode-set` 和 `device-select`。`processes` 用于证明 frida-server 可用；仅看到 USB 设备不等于能够注入。

标准 Run 由 Frida spawn 目标，通常不需要先 `adb-open-app`。只有用户明确要求先操作 app，或项目流程不是标准 spawn 时，才使用 ADB 生命周期命令。

### 可选 Attach

Attach 前先调用 `processes --scope apps` 或 `processes --scope running`，确认目标已经存在。根据任务设置 Attach Script 和 Target，再执行一次 Attach：

```bash
python3 <skill-dir>/scripts/zafrida_api.py attach-script-set --path /absolute/attach.js
python3 <skill-dir>/scripts/zafrida_api.py target-set --target <process-name-or-pid>
python3 <skill-dir>/scripts/zafrida_api.py attach
python3 <skill-dir>/scripts/zafrida_api.py wait-session --type attach --state running --timeout 15 --interval 0.5
python3 <skill-dir>/scripts/zafrida_api.py attach-log-tail --max-bytes 65536
```

目标不存在时不要连续重试 Attach；先刷新进程列表并核对名称、identifier 或 PID。

## Remote 模式

Remote 使用 `-H <host>:<port>` 连接远端 frida-server。`devices` 中的 Remote 条目可以由配置合成，不能证明网络端点可用；必须通过 `processes` 或一次有界诊断验证连接。

### 标准 Run

```bash
python3 <skill-dir>/scripts/zafrida_api.py state
python3 <skill-dir>/scripts/zafrida_api.py mode-set --mode remote --host <host> --port <port>
python3 <skill-dir>/scripts/zafrida_api.py device-select --host <host>:<port>
python3 <skill-dir>/scripts/zafrida_api.py processes --scope apps
python3 <skill-dir>/scripts/zafrida_api.py target-set --target <spawn-target>
python3 <skill-dir>/scripts/zafrida_api.py run-script-set --path /absolute/agent.js
python3 <skill-dir>/scripts/zafrida_api.py run
python3 <skill-dir>/scripts/zafrida_api.py wait-session --type run --state running --timeout 15 --interval 0.5
python3 <skill-dir>/scripts/zafrida_api.py run-log-tail --max-bytes 65536
```

配置已经正确时不要重复写入 mode/host/port。非 loopback 地址直接连接远端端点；loopback Android 场景中，ZAFrida 会尝试 ADB port forwarding，因此还要保证 ADB 设备选择和转发链路正确。转发失败或端口不可达时，先运行 `diagnostics`，不能直接反复 Run。

标准 Remote Run 仍由远端 frida-server spawn Target，不要求先手动打开 app。Remote Attach 与 USB Attach 一样是可选阶段：先用 `processes` 证明目标存在，再设置 Attach Script、Target，执行一次 Attach 并读取 Attach 日志。

需要 TLS certificate、token、Origin、keepalive 或其他 Remote 参数时，通过项目允许的 Extra Args 明确传入；不得猜测凭据或连接参数。

## 失败后的分流

- USB 设备消失、frida-server 不可用或版本不匹配：进入 [recovery.md](recovery.md) 的 USB 恢复。
- Remote `unable to connect`、`transport is closed`、端口或 forwarding 问题：进入 Remote 恢复。
- 日志显示脚本编译、Frida 17 API 或目标错误：处理脚本/目标，不要误做设备重连。
- 任何第二次 Run/Attach 前先确认上一次会话已停止，并保持重试次数有界。
