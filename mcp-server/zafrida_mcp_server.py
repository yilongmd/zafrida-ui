#!/usr/bin/env python3
"""
ZAFrida MCP Server — legacy、feature-frozen 的 HTTP API 兼容适配器。

注册方式（Claude Code）：
    claude mcp add zafrida -- python3 /path/to/zafrida_mcp_server.py

支持的工具（27 个）：
    状态与诊断: health, state, diagnostics
    设备与进程: devices, processes, device_select, connection_mode_set
    项目管理:   project_current, project_select, project_create
    脚本与参数: target_set, run_script_set, attach_script_set, extra_args_set
    ADB 操作:   adb_force_stop, adb_open_app
    会话控制:   run, stop, attach, stop_attach
    控制台:     console_clear
    日志读取:   run_log_path, run_log_content, run_log_lines,
               attach_log_path, attach_log_content, attach_log_lines
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

DEFAULT_BASE_URL = "http://127.0.0.1:17839/zafrida/api/v1"

# ─────────────────────────────────────────────
# HTTP 调用层（复用 zafrida_skill_cli.py 的逻辑）
# ─────────────────────────────────────────────

def _base_url() -> str:
    raw = os.environ.get("ZAFRIDA_API_BASE", DEFAULT_BASE_URL).strip()
    if raw.endswith("/"):
        raw = raw[:-1]
    return raw


def _call_api(endpoint: str, method: str = "GET", params: dict[str, str] | None = None) -> dict:
    """发送 HTTP 请求并返回 JSON 响应。"""
    payload = params or {}
    url = f"{_base_url()}{endpoint}"
    data_bytes = None
    headers = {"Accept": "application/json"}

    if method == "GET":
        if payload:
            url = f"{url}?{urllib.parse.urlencode(payload)}"
    else:
        data_bytes = urllib.parse.urlencode(payload).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    request = urllib.request.Request(url=url, method=method, data=data_bytes, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            text = response.read().decode("utf-8", errors="replace")
            if not text:
                return {}
            return json.loads(text)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if body:
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                pass
        return {"ok": False, "status": exc.code, "message": body or str(exc)}
    except urllib.error.URLError as exc:
        return {"ok": False, "status": 0, "message": str(exc)}


# ─────────────────────────────────────────────
# 工具定义
# ─────────────────────────────────────────────

TOOLS: list[Tool] = [
    # ── 状态与诊断 ──
    Tool(
        name="health",
        description="健康检查 — 确认 ZAFrida Skills HTTP API 是否可达",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="state",
        description="完整状态汇总 — 项目/设备/脚本/会话状态/日志文件大小（不含日志内容）",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="diagnostics",
        description="环境诊断 — 检查 Python SDK / Frida 路径 / 版本 / 设备枚举 / 设备连通 / ADB（6 项）",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),

    # ── 设备与进程 ──
    Tool(
        name="devices",
        description="列出所有已连接设备（调用 frida-ls-devices）",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="processes",
        description="列出当前设备的进程/应用",
        inputSchema={
            "type": "object",
            "properties": {
                "scope": {
                    "type": "string",
                    "enum": ["running", "apps", "installed"],
                    "description": "列表范围：running（运行中进程）、apps（运行中应用）、installed（已安装应用）",
                    "default": "running",
                },
            },
            "required": [],
        },
    ),
    Tool(
        name="device_select",
        description="选择设备（通过设备 ID 或远程主机地址，二选一）",
        inputSchema={
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "设备 ID"},
                "host": {"type": "string", "description": "远程设备地址"},
            },
            "required": [],
        },
    ),
    Tool(
        name="connection_mode_set",
        description="设置连接模式（usb/remote/gadget）",
        inputSchema={
            "type": "object",
            "properties": {
                "mode": {"type": "string", "enum": ["usb", "remote", "gadget"], "description": "连接模式"},
                "host": {"type": "string", "description": "远程主机地址"},
                "port": {"type": "integer", "description": "远程端口"},
            },
            "required": ["mode"],
        },
    ),

    # ── 项目管理 ──
    Tool(
        name="project_current",
        description="获取当前活跃项目及项目列表",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="project_select",
        description="切换活跃项目",
        inputSchema={
            "type": "object",
            "properties": {"name": {"type": "string", "description": "项目名称"}},
            "required": ["name"],
        },
    ),
    Tool(
        name="project_create",
        description="新建项目",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "项目名称"},
                "platform": {"type": "string", "enum": ["android", "ios"], "description": "目标平台", "default": "android"},
            },
            "required": ["name"],
        },
    ),

    # ── 脚本与参数 ──
    Tool(
        name="target_set",
        description="设置目标应用包名",
        inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string", "description": "目标包名"}},
            "required": ["target"],
        },
    ),
    Tool(
        name="run_script_set",
        description="设置 Run 脚本路径（绝对路径）",
        inputSchema={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "脚本绝对路径"}},
            "required": ["path"],
        },
    ),
    Tool(
        name="attach_script_set",
        description="设置 Attach 脚本路径（绝对路径）",
        inputSchema={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "脚本绝对路径"}},
            "required": ["path"],
        },
    ),
    Tool(
        name="extra_args_set",
        description="设置额外命令行参数",
        inputSchema={
            "type": "object",
            "properties": {"value": {"type": "string", "description": "参数值", "default": ""}},
            "required": [],
        },
    ),

    # ── ADB 操作 ──
    Tool(
        name="adb_force_stop",
        description="ADB 强制停止应用（默认使用当前 target）",
        inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string", "description": "目标包名（可选，默认用当前 target）"}},
            "required": [],
        },
    ),
    Tool(
        name="adb_open_app",
        description="ADB 启动应用（默认使用当前 target）",
        inputSchema={
            "type": "object",
            "properties": {"target": {"type": "string", "description": "目标包名（可选，默认用当前 target）"}},
            "required": [],
        },
    ),

    # ── 会话控制 ──
    Tool(name="run", description="启动 Run 会话", inputSchema={"type": "object", "properties": {}, "required": []}),
    Tool(name="stop", description="停止 Run 会话", inputSchema={"type": "object", "properties": {}, "required": []}),
    Tool(name="attach", description="启动 Attach 会话", inputSchema={"type": "object", "properties": {}, "required": []}),
    Tool(name="stop_attach", description="停止 Attach 会话", inputSchema={"type": "object", "properties": {}, "required": []}),

    # ── 控制台 ──
    Tool(
        name="console_clear",
        description="清空控制台",
        inputSchema={
            "type": "object",
            "properties": {
                "type": {"type": "string", "enum": ["run", "attach"], "description": "控制台类型", "default": "run"},
            },
            "required": [],
        },
    ),

    # ── 日志读取 ──
    Tool(
        name="run_log_path",
        description="获取 Run 日志路径和文件大小",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="run_log_content",
        description="读取 Run 日志内容（适合小文件 < 200KB）",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "覆盖日志文件路径"},
                "maxBytes": {"type": "integer", "description": "仅读取末尾 N 字节（0=全部）", "default": 0},
            },
            "required": [],
        },
    ),
    Tool(
        name="run_log_lines",
        description="按行读取 Run 日志（适合中大文件，最多 2000 行/次）",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "覆盖日志文件路径"},
                "start": {"type": "integer", "description": "起始行号（1-based）", "default": 1},
                "count": {"type": "integer", "description": "读取行数", "default": 100},
            },
            "required": [],
        },
    ),
    Tool(
        name="attach_log_path",
        description="获取 Attach 日志路径和文件大小",
        inputSchema={"type": "object", "properties": {}, "required": []},
    ),
    Tool(
        name="attach_log_content",
        description="读取 Attach 日志内容（适合小文件 < 200KB）",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "覆盖日志文件路径"},
                "maxBytes": {"type": "integer", "description": "仅读取末尾 N 字节（0=全部）", "default": 0},
            },
            "required": [],
        },
    ),
    Tool(
        name="attach_log_lines",
        description="按行读取 Attach 日志（适合中大文件，最多 2000 行/次）",
        inputSchema={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "覆盖日志文件路径"},
                "start": {"type": "integer", "description": "起始行号（1-based）", "default": 1},
                "count": {"type": "integer", "description": "读取行数", "default": 100},
            },
            "required": [],
        },
    ),
]


# ─────────────────────────────────────────────
# 工具名 → (HTTP 方法, 端点, 参数映射) 路由表
# ─────────────────────────────────────────────

def _route(name: str, args: dict[str, Any]) -> dict:
    """将 MCP 工具调用映射到 HTTP API 请求。"""
    routes: dict[str, tuple[str, str]] = {
        "health":              ("GET",  "/health"),
        "state":               ("GET",  "/state"),
        "diagnostics":         ("GET",  "/diagnostics"),
        "devices":             ("GET",  "/devices"),
        "processes":           ("GET",  "/processes"),
        "device_select":       ("POST", "/device/select"),
        "connection_mode_set": ("POST", "/connection-mode/set"),
        "project_current":     ("GET",  "/project/current"),
        "project_select":      ("POST", "/project/select"),
        "project_create":      ("POST", "/project/create"),
        "target_set":          ("POST", "/target/set"),
        "run_script_set":      ("POST", "/run-script/set"),
        "attach_script_set":   ("POST", "/attach-script/set"),
        "extra_args_set":      ("POST", "/extra-args/set"),
        "adb_force_stop":      ("POST", "/adb/force-stop"),
        "adb_open_app":        ("POST", "/adb/open-app"),
        "run":                 ("POST", "/run"),
        "stop":                ("POST", "/stop"),
        "attach":              ("POST", "/attach"),
        "stop_attach":         ("POST", "/stop-attach"),
        "console_clear":       ("POST", "/console/clear"),
        "run_log_path":        ("GET",  "/run-log/path"),
        "run_log_content":     ("GET",  "/run-log/content"),
        "run_log_lines":       ("GET",  "/run-log/lines"),
        "attach_log_path":     ("GET",  "/attach-log/path"),
        "attach_log_content":  ("GET",  "/attach-log/content"),
        "attach_log_lines":    ("GET",  "/attach-log/lines"),
    }

    if name not in routes:
        return {"ok": False, "message": f"未知工具: {name}"}

    method, endpoint = routes[name]

    # 将 MCP 参数转为 HTTP 请求参数（过滤空值）
    params: dict[str, str] = {}
    for key, value in args.items():
        if value is not None and value != "":
            params[key] = str(value)

    return _call_api(endpoint, method, params if params else None)


# ─────────────────────────────────────────────
# MCP Server
# ─────────────────────────────────────────────

server = Server("zafrida")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any] | None) -> list[TextContent]:
    result = _route(name, arguments or {})
    return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
