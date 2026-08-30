# 不稳定设备恢复

恢复必须有界。除非证据表明配置错误，否则保留用户当前项目、环境、目标和脚本。

## 重试分类

可以自动重试：

- `health`、`capabilities`、`state`、`session-status`
- `devices`、`processes`
- `project-current`、`python-env-current`
- 日志 path/list/content/lines/tail

不得自动重放：

- `run` 或 `attach`：延迟到达的第一次请求可能已经启动进程。
- `project-create`：重试可能与已创建目录冲突。
- `adb-open-app`：会改变设备状态。
- 项目、环境、脚本、目标设置：除非请求值仍未生效并且用户已授权修改。

## USB 恢复

正常 USB Run/Attach 流程见 [standard-modes.md](standard-modes.md)。只有标准流程失败时才进入本节。

1. 调用 `health`，再读取 `state`。
2. 调用 `wait-device --type usb --timeout 60 --interval 2`；已知设备 ID 时按 ID 等待。
3. 使用返回的 ID 执行 `device-select`。
4. 执行 `processes --scope apps`，区分“能枚举设备”和“frida-server 真正可用”。
5. 进程列表失败时只运行一次 `diagnostics`，并根据 `errorCode` 处理：
   - `FRIDA_COMMAND_TIMEOUT` 或 `FRIDA_DEVICE_UNAVAILABLE`：对只读发现操作做有界退避重试。
   - `PYTHON_ENVIRONMENT_INVALID`：停止重试，修复或选择正确环境。
   - `FRIDA_COMMAND_FAILED`：读取 stderr/日志，盲目重复通常无效。

ADB 和 Frida 是两条独立链路。`adb devices` 正常不代表 frida-server 已运行或版本匹配；Remote Frida 也可能在没有 ADB 设备时工作。

## Remote 恢复

正常 Remote Run/Attach 流程见 [standard-modes.md](standard-modes.md)。只有标准流程失败时才进入本节。

1. 通过 `state` 确认连接模式和准确的 `host:port`。
2. Android loopback 转发场景通过 `diagnostics` 检查 ADB。
3. 调用 `processes`；`devices` 中的 Remote 条目只代表配置，不代表连接成功。
4. 传输关闭时，短暂等待后只重试 `processes`；`session-status` 未证明会话停止前，不得重放 Run/Attach。

## Gadget 恢复

任何操作前读取 [gadget.md](gadget.md)。由 Zygisk 加载的 Gadget 需要先关闭目标 app、重新打开并等待 Gadget 初始化，再执行项目所需的 Run 或 Attach。不能把 `connection closed` 当成普通 Remote 重试，也不能对同一个残留 app 进程连续执行 Run。

## 目标与进程恢复

- `unable to find process` 或 Attach 立即退出：刷新 `processes --scope apps`，再设置准确标识。
- spawn 目标未安装：修改目标前先用 `processes --scope installed` 检查。
- app 残留运行：获得用户授权后执行 `adb-force-stop`，验证已停止，再启动一次。
- 版本不匹配：比较 `python-env-test` 的 Frida 版本与设备端 frida-server，选择预期的共享 Frida 16/17 环境，不要修改全局 PATH 来碰运气。

超时后返回最后一次 JSON、已经执行的命令和日志位置，不得继续无限恢复。
