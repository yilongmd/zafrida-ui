# Gadget 模式生命周期

ZAFrida Gadget 模式使用 `-H <host>:<port> -F`，不会 spawn 目标。在由 Zygisk 加载 Gadget 的部署中，打开 app 后 Zygisk 才会把 Gadget 注入目标进程；Gadget listen 模式等待 Frida 连接时，app 可能表现为暂停。因此必须先打开 app 并等待 Gadget 初始化，再执行项目需要的 Run 或 Attach。

统一使用：

```bash
python3 <skill-dir>/scripts/zafrida_api.py <command> [arguments]
```

在 ZAFrida 源码目录中，也可以使用兼容入口 `skills-cli/zafrida_skill_cli.py`。

## 先验证上下文

读取 `state`，确认：

- 预期的 ZAFrida 项目处于活动状态；
- `connectionMode` 为 `gadget`，host/port 正确；
- Target 是 `adb-force-stop` 和 `adb-open-app` 使用的 Android 包名；
- Run Script 以及当前任务需要时的 Attach Script 路径正确；
- ADB 转发需要指定设备时，选中了正确的 USB 设备。

loopback Gadget 启动 Frida 前，ZAFrida 会尝试 `adb forward tcp:<port> tcp:<port>`。ADB 或转发不确定时运行 `diagnostics`。`devices` 中的 Gadget 条目只证明配置存在，不代表 Gadget 已就绪。

## 全新 Gadget Run

只停止 `state` 或 `session-status` 显示仍在运行的会话。全新实验中，如果 Run 和 Attach 都存活，应分别停止：

```bash
# 仅在 Run 正在运行时执行。
python3 <skill-dir>/scripts/zafrida_api.py stop
python3 <skill-dir>/scripts/zafrida_api.py wait-session --type run --state stopped --timeout 5 --interval 0.25

# 仅在 Attach 正在运行时执行。
python3 <skill-dir>/scripts/zafrida_api.py stop-attach
python3 <skill-dir>/scripts/zafrida_api.py wait-session --type attach --state stopped --timeout 5 --interval 0.25

# 只有实际发出过 stop 时才需要短暂等待；1 秒只是常用基线。
sleep 1

# 重置 app 和残留 Gadget 传输。ADB API 当前是异步 accepted。
python3 <skill-dir>/scripts/zafrida_api.py adb-force-stop
sleep 1

# 打开 app，让 Zygisk 注入并初始化 Gadget。
python3 <skill-dir>/scripts/zafrida_api.py adb-open-app
sleep 3

# 只连接一次，再验证状态并读取证据。
python3 <skill-dir>/scripts/zafrida_api.py run
python3 <skill-dir>/scripts/zafrida_api.py wait-session --type run --state running --timeout 15 --interval 0.5
python3 <skill-dir>/scripts/zafrida_api.py state
python3 <skill-dir>/scripts/zafrida_api.py run-log-tail --max-bytes 65536
```

这些等待都是默认基线，不是协议常量：

- 发出 session stop 后先用 `wait-session`，再根据当前平台和项目决定是否追加短暂 settle；
- `adb-force-stop` 后的等待取决于设备和系统；1 秒是常见起点；
- `adb-open-app` 后必须等待 Gadget 注入完成，具体时间由设备、注入方式和项目决定，2–3 秒只能作为起点；
- Run 后用 `wait-session` 判断会话状态，不用固定 sleep 代替；
- 业务初始化完成时间必须由当前项目决定，优先等待明确日志或就绪信号。

`run` 只有在启动真正进入 SessionService 后才会内部停止同类型会话，不能作为可靠的 Gadget 重置：当前 Run 操作被禁用时，API 仍可能返回 accepted 但没有重启；内部 stop 也不等待进程完全退出。因此保留上述基于状态的显式停止流程。

## Attach 是可选阶段

不要默认执行 Attach。有些项目只需要 Run；只有用户任务、项目配置或明确实验步骤要求 Attach 时才执行。

Attach-only 场景同样必须先完成会话清理、force-stop、open-app 和 Gadget 就绪等待，然后设置 Attach Script，执行一次 `attach`，并等待 Attach 进入 running。不能在 app 尚未加载 Gadget 时 Attach。

Run 后再 Attach 时：

1. 先确认 Run 已 running。
2. 根据当前项目的就绪条件决定是否等待以及等待多久；不存在通用固定秒数。
3. 需要更换实验脚本时，执行 `attach-script-set --path /absolute/script.js`。
4. 只执行一次 `attach`，再调用 `wait-session --type attach --state running`。
5. 读取 `state` 和两份日志。app 被杀或崩溃时，Run 与 Attach 可能一起断开；Run 日志中的 `Connection terminated` 不能单独证明 Attach 顶掉了 Run。

部分 Gadget 部署允许 Run 与 Attach 同时存活，另一些部署可能不同。不能假设 Gadget 只接受一个连接，也不能假设 Attach 必然替换 Run，必须以当前状态和日志为准。

关键 Attach hook 尽量自包含，避免依赖不可见的 Run 脚本状态。

## 失败处理

- 出现 `connection closed` 或 `transport is closed` 时，先读取 session 状态和对应日志，不能立即重放 Run。
- app/Gadget 进程残留时，执行一次完整的 stop → force-stop → open → 就绪等待；再次 Run 必须仍在用户授权范围内。
- Run 或 Attach 立即退出时，修改脚本、目标、环境或设备前先检查退出日志。
- 恢复必须有界；无法恢复时返回最后状态、日志路径/offset 和已执行命令。

## 日志

小日志可以直接读取：

```bash
python3 <skill-dir>/scripts/zafrida_api.py run-log-content --max-bytes 200000
python3 <skill-dir>/scripts/zafrida_api.py attach-log-content --max-bytes 200000
```

大日志或增长中的日志优先使用 `run-log-tail` / `attach-log-tail` 并保存 `nextOffset`。历史文件使用 `logs-list`、`*-log-path` 或 `*-log-lines`。宿主确实提供 large-text-viewer 时，可以把 API 返回的准确路径交给它并使用 info/search/lines；不能假设该工具一定存在。日志文件名包含时间，并可能包含清理后的包名和 Run/Attach 标记，应通过 API 获取路径，不要手工构造。
