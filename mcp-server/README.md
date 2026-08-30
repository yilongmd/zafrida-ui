# ZAFrida MCP Server

> **维护状态：Legacy / feature-frozen。** 新的设备恢复、Python 环境和增量日志能力只在 `skills-template/zafrida-http-control/` 的 Skill + CLI 中扩展。MCP 适配器暂时保留现有 27 个工具，给已经注册它的客户端一个兼容窗口；计划在后续破坏性版本中单独移除。新接入请直接使用 Skill/CLI 和本地 HTTP API。

将 ZAFrida Skills HTTP API 封装为 [MCP (Model Context Protocol)](https://modelcontextprotocol.io) 服务，支持 Claude Code、Cursor、Windsurf 等 AI 工具一键注册。

## 前置条件

- ZAFrida 插件已安装，ToolWindow 至少打开过一次
- Skills HTTP API 已启用（Settings → ZAFrida → Skills HTTP API）
- Python 3.10+

## 安装

```bash
pip install -r requirements.txt
```

## 注册

### Claude Code

```bash
claude mcp add zafrida -- python3 /path/to/mcp-server/zafrida_mcp_server.py
```

### Cursor

在 `.cursor/mcp.json` 中添加：

```json
{
  "mcpServers": {
    "zafrida": {
      "command": "python3",
      "args": ["/path/to/mcp-server/zafrida_mcp_server.py"]
    }
  }
}
```

### 自定义 API 地址

默认连接 `http://127.0.0.1:17839/zafrida/api/v1`，可通过环境变量覆盖：

```bash
ZAFRIDA_API_BASE=http://127.0.0.1:12345/zafrida/api/v1 python3 zafrida_mcp_server.py
```

## 提供的工具（27 个）

| 分类 | 工具 | 说明 |
|------|------|------|
| 状态与诊断 | `health` | 健康检查 |
| | `state` | 完整状态汇总 |
| | `diagnostics` | 环境诊断（6 项检查） |
| 设备与进程 | `devices` | 列出已连接设备 |
| | `processes` | 列出进程/应用 |
| | `device_select` | 选择设备 |
| | `connection_mode_set` | 设置连接模式 |
| 项目管理 | `project_current` | 当前项目 |
| | `project_select` | 切换项目 |
| | `project_create` | 新建项目 |
| 脚本与参数 | `target_set` | 设置目标包名 |
| | `run_script_set` | 设置 Run 脚本 |
| | `attach_script_set` | 设置 Attach 脚本 |
| | `extra_args_set` | 设置额外参数 |
| ADB | `adb_force_stop` | 强制停止应用 |
| | `adb_open_app` | 启动应用 |
| 会话控制 | `run` | 启动 Run |
| | `stop` | 停止 Run |
| | `attach` | 启动 Attach |
| | `stop_attach` | 停止 Attach |
| 控制台 | `console_clear` | 清空控制台 |
| 日志 | `run_log_path` | Run 日志路径+大小 |
| | `run_log_content` | 读取 Run 日志内容 |
| | `run_log_lines` | 按行读取 Run 日志 |
| | `attach_log_path` | Attach 日志路径+大小 |
| | `attach_log_content` | 读取 Attach 日志内容 |
| | `attach_log_lines` | 按行读取 Attach 日志 |
