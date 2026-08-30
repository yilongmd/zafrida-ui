---
name: zafrida-http-control
description: 通过本地回环 HTTP API 控制和诊断 ZAFrida JetBrains 插件。适用于项目与 Python 环境配置、Frida 设备和进程发现、Run/Attach 生命周期控制、不稳定设备恢复以及增量日志分析；仅解释或编辑普通 Frida 脚本时不要使用。
---

# ZAFrida HTTP 控制

使用相对本文件的 `scripts/zafrida_api.py`。不要假设它已复制到全局工具目录。

## 建立上下文

先执行只读命令：

```bash
python3 <skill-dir>/scripts/zafrida_api.py health
python3 <skill-dir>/scripts/zafrida_api.py capabilities
python3 <skill-dir>/scripts/zafrida_api.py state
```

API 无法连接时，请用户打开 ZAFrida ToolWindow，并启用 `Settings/Preferences → ZAFrida → Skills HTTP API`。默认地址为 `http://127.0.0.1:17839/zafrida/api/v1`，可通过 `ZAFRIDA_API_BASE` 或 `--base-url` 覆盖。

把响应中的 `errorCode` 和 `retryable` 视为权威信息。修改命令返回 `accepted: true` 只表示 UI 接受了请求，不代表 Frida 进程已经运行；必须继续使用 `wait-session` 验证，并读取日志。

## 安全与重试边界

- 仅对只读的发现、状态和日志操作进行有界重试。
- 不要自动重放 `run`、`attach`、`project-create`、`adb-open-app` 或其他具有外部副作用的操作；再次执行前先检查当前状态。
- `stop` 和 `stop-attach` 可用于安全清理，但应说明原来是否存在会话。
- 达到超时后停止恢复，返回最后一次结构化错误，不得无限循环。
- 除非用户明确要求，或当前操作确实依赖，不要替换项目的 Python 环境、目标、脚本、设备或连接模式。

## 按任务读取资料

- 项目、Python 环境、连接设置、脚本和普通会话控制：读取 [references/operations.md](references/operations.md)。
- USB 或 Remote 模式的标准 Run/Attach：操作前读取 [references/standard-modes.md](references/standard-modes.md)。
- 任何 Gadget 模式的 Run/Attach 或 Gadget 传输恢复：操作前必须读取 [references/gadget.md](references/gadget.md)。Gadget 需要协调 app 生命周期，不能套用普通 Run 流程。
- USB/网络不稳定、Frida server 版本不匹配、残留进程和有界恢复：读取 [references/recovery.md](references/recovery.md)。
- Run/Attach 失败、agent 输出或用户要求“读取日志”：选择日志命令前读取 [references/logs.md](references/logs.md)。

## 默认执行方式

1. 读取 `state`；仅在目标项目不是当前项目时才切换。
2. 读取 `python-env-current`；环境刚变化或 Frida 版本不确定时，运行 `python-env-test`。
3. 手机不稳定时使用 `wait-device`，再选择匹配设备，并在需要时查询 `processes`。
4. 只设置缺失或用户明确要求修改的字段。
5. USB/Remote 模式下只执行一次 `run` 或 `attach`，随后用 `wait-session` 等待 `running`；Gadget 模式改用专用流程。
6. 读取对应的 `*-log-tail`，保存 `nextOffset` 供增量轮询。
7. 失败时先根据日志和错误分类，再选择影响范围最小的恢复动作。

所有命令只输出一个 JSON 对象；`ok` 为 false 时返回非零退出码。
