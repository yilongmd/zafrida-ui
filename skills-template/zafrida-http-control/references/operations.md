# ZAFrida 操作参考

统一使用：

```bash
python3 <skill-dir>/scripts/zafrida_api.py <command> [arguments]
```

通用参数可以放在子命令前后：

- `--base-url URL`：覆盖 API 地址。
- `--request-timeout SECONDS`：单次请求超时，默认 30 秒。
- `--retries N --retry-delay SECONDS`：仅为安全操作设置有界重试。
- `--compact`：输出紧凑 JSON。

## 只读上下文

| 命令 | 用途 |
|---|---|
| `health` | 检查服务、端口和 Session 面板是否就绪。 |
| `capabilities` | 查看功能、脚本扩展名、重试分类和响应限制。 |
| `state` | 查看当前项目、UI 字段、设备、会话和日志元数据。 |
| `session-status` | 轻量查询 Run/Attach 状态。 |
| `diagnostics` | 检查 Python、Frida 工具与版本、设备和 ADB。 |
| `project-current` | 查看当前项目、已登记项目和项目配置。 |
| `python-env-current` | 查看实际解释器、环境根目录、来源、PATH 和工具路径。 |

## 项目与 Python 环境

```bash
python3 <skill-dir>/scripts/zafrida_api.py project-select --name demo
python3 <skill-dir>/scripts/zafrida_api.py project-create --name demo --platform android

# 可填写环境根目录或解释器文件；多个项目可以复用同一路径。
python3 <skill-dir>/scripts/zafrida_api.py python-env-set --path /abs/path/to/venv
python3 <skill-dir>/scripts/zafrida_api.py python-env-test --path /abs/path/to/venv

# 清除覆盖，恢复使用 PyCharm 项目解释器。
python3 <skill-dir>/scripts/zafrida_api.py python-env-set --path ""
python3 <skill-dir>/scripts/zafrida_api.py python-env-test
```

支持 system/pyenv、venv/virtualenv、Conda、uv、Poetry、Pipenv 和 Hatch 等本地环境。远程 SSH/Docker/WSL SDK 不能启动本地 Frida 进程。已解析的 IDE 环境或项目显式环境都是权威来源；缺少 `frida`、`frida-ps` 或 `frida-ls-devices` 时必须报错，不能静默切换到其他 Frida 版本。

## 设备、进程与连接

```bash
python3 <skill-dir>/scripts/zafrida_api.py devices --retries 2
python3 <skill-dir>/scripts/zafrida_api.py wait-device --type usb --timeout 60 --interval 2
python3 <skill-dir>/scripts/zafrida_api.py device-select --id <returned-device-id>
python3 <skill-dir>/scripts/zafrida_api.py device-select --host 127.0.0.1:14725
python3 <skill-dir>/scripts/zafrida_api.py mode-set --mode usb
python3 <skill-dir>/scripts/zafrida_api.py mode-set --mode remote --host 127.0.0.1 --port 14725
python3 <skill-dir>/scripts/zafrida_api.py mode-set --mode gadget --host 127.0.0.1 --port 14725
python3 <skill-dir>/scripts/zafrida_api.py processes --scope running
python3 <skill-dir>/scripts/zafrida_api.py processes --scope apps
python3 <skill-dir>/scripts/zafrida_api.py processes --scope installed
```

`wait-device` 未指定 `--id`、`--host` 或 `--type` 时匹配任意设备。未知具体 USB ID 时使用 `--type usb`。`devices` 中合成的 Remote/Gadget 条目只代表配置存在，不能证明端点可连接。

USB 和 Remote 的标准启动与验证流程见 [standard-modes.md](standard-modes.md)。

Gadget 不是普通 Remote Run。执行 Gadget Run/Attach 前必须读取 [gadget.md](gadget.md)。

## 脚本与运行参数

支持 `.js` 和 `.ts`。Frida 17 的 frida-tools REPL 可以编译通过 `-l` 加载的 `.ts`，并提供标准 Java/ObjC bridge；Frida 16 应使用预编译 JavaScript。npm 或第三方模块仍需有效的 TypeScript 工程和构建配置。

```bash
python3 <skill-dir>/scripts/zafrida_api.py target-set --target com.example.app
python3 <skill-dir>/scripts/zafrida_api.py run-script-set --path /abs/path/agent.ts
python3 <skill-dir>/scripts/zafrida_api.py attach-script-set --path /abs/path/attach.js
python3 <skill-dir>/scripts/zafrida_api.py extra-set --value=--realm=emulated
```

主脚本总是最先加载。Frida CLI 支持重复的 `-l/--load`，因此可通过 `extra-set` 添加脚本，例如 `--value='-l /abs/path/extra.js -l /abs/path/trace.js'`。保持加载顺序，含空格路径必须正确引用。脚本共享状态或存在顺序依赖时，优先使用一个入口脚本和 imports。

## 会话生命周期

```bash
python3 <skill-dir>/scripts/zafrida_api.py run
python3 <skill-dir>/scripts/zafrida_api.py wait-session --type run --state running --timeout 15
python3 <skill-dir>/scripts/zafrida_api.py stop

# 只有当前任务确实需要 Attach 时才执行。
python3 <skill-dir>/scripts/zafrida_api.py attach
python3 <skill-dir>/scripts/zafrida_api.py wait-session --type attach --state running --timeout 15
python3 <skill-dir>/scripts/zafrida_api.py stop-attach
```

不能把 `accepted: true` 当成成功。`wait-session` 很快回到 `stopped` 时，应读取对应日志判断启动、编译、目标或传输错误。

## ADB 与 Console

```bash
python3 <skill-dir>/scripts/zafrida_api.py adb-force-stop
python3 <skill-dir>/scripts/zafrida_api.py adb-open-app --target com.example.app
python3 <skill-dir>/scripts/zafrida_api.py console-clear --type run
```

当前 ADB API 是异步的：响应只确认请求已接受，不代表设备端动作已经完成。应结合项目所需等待、`processes`、`wait-device` 或日志验证。
