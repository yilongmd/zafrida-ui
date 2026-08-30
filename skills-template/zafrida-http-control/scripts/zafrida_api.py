#!/usr/bin/env python3
"""CLI for ZAFrida's loopback HTTP API."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple


DEFAULT_BASE_URL = "http://127.0.0.1:17839/zafrida/api/v1"
DEFAULT_REQUEST_TIMEOUT = 30.0


def normalize_base_url(raw: str) -> str:
    return raw.strip().rstrip("/")


def transport_error(message: str) -> Dict[str, Any]:
    return {
        "ok": False,
        "status": 0,
        "errorCode": "API_UNREACHABLE",
        "retryable": True,
        "message": message,
    }


def decode_response(status: int, raw: str) -> Tuple[int, Dict[str, Any]]:
    if not raw:
        return status, {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        return status, {
            "ok": False,
            "status": status,
            "errorCode": "INVALID_JSON_RESPONSE",
            "retryable": status >= 500,
            "message": f"ZAFrida returned invalid JSON: {exc}",
            "raw": raw[:4000],
        }
    if not isinstance(payload, dict):
        return status, {
            "ok": False,
            "status": status,
            "errorCode": "INVALID_JSON_RESPONSE",
            "retryable": False,
            "message": "ZAFrida returned a non-object JSON response",
        }
    return status, payload


def call_api_once(
    base_url: str,
    endpoint: str,
    method: str,
    params: Dict[str, str],
    timeout: float,
) -> Tuple[int, Dict[str, Any]]:
    url = f"{normalize_base_url(base_url)}{endpoint}"
    data = None
    headers = {
        "Accept": "application/json",
        "User-Agent": "ZAFrida-Skill-CLI/2",
    }
    if method == "GET":
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
    else:
        data = urllib.parse.urlencode(params).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    try:
        request = urllib.request.Request(url=url, method=method, data=data, headers=headers)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            return decode_response(response.status, raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        return decode_response(exc.code, raw or str(exc))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return 0, transport_error(str(exc))


def call_api(
    base_url: str,
    endpoint: str,
    method: str = "GET",
    params: Optional[Dict[str, str]] = None,
    timeout: float = DEFAULT_REQUEST_TIMEOUT,
    retries: int = 0,
    retry_delay: float = 1.0,
) -> Tuple[int, Dict[str, Any]]:
    payload = params or {}
    safe_to_retry = method == "GET" or endpoint == "/python-environment/test"
    attempts = max(0, retries) + 1
    last_status = 0
    last_payload: Dict[str, Any] = transport_error("No request attempted")
    for attempt in range(attempts):
        last_status, last_payload = call_api_once(base_url, endpoint, method, payload, timeout)
        if "retryable" in last_payload:
            retryable = bool(last_payload.get("retryable"))
        else:
            retryable = last_status == 0 or last_status >= 500
        if not safe_to_retry or not retryable or attempt + 1 >= attempts:
            break
        delay = min(5.0, max(0.0, retry_delay) * (2 ** attempt))
        if delay > 0:
            time.sleep(delay)
    return last_status, last_payload


def print_json(payload: Dict[str, Any], compact: bool) -> None:
    if compact:
        print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))


def add_path_and_limit(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--path", help="日志文件路径；省略时使用当前会话日志")
    parser.add_argument("--max-bytes", type=int, default=0, help="最多读取的字节数")


def build_command_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ZAFrida 本地 API 命令行助手")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("health", "健康检查"),
        ("capabilities", "查询 API 能力与限制"),
        ("state", "完整状态汇总"),
        ("session-status", "Run/Attach 会话状态"),
        ("diagnostics", "环境诊断"),
        ("project-current", "当前项目和项目列表"),
        ("python-env-current", "当前有效 Python 环境"),
        ("devices", "列出 Frida 设备"),
        ("run", "启动 Run 会话"),
        ("stop", "停止 Run 会话"),
        ("attach", "启动 Attach 会话"),
        ("stop-attach", "停止 Attach 会话"),
        ("run-log-path", "当前 Run 日志路径"),
        ("attach-log-path", "当前 Attach 日志路径"),
    ):
        sub.add_parser(name, help=help_text)

    project_select = sub.add_parser("project-select", help="切换当前项目")
    project_select.add_argument("--name", required=True)

    project_create = sub.add_parser("project-create", help="新建项目")
    project_create.add_argument("--name", required=True)
    project_create.add_argument("--platform", choices=["android", "ios"], default="android")

    python_set = sub.add_parser("python-env-set", help="设置当前项目 Python 环境；空字符串恢复 IDE 默认")
    python_set.add_argument("--path", default="")

    python_test = sub.add_parser("python-env-test", help="测试当前或指定 Python 环境中的 Frida 工具")
    python_test.add_argument("--path")

    processes = sub.add_parser("processes", help="列出当前设备进程或应用")
    processes.add_argument("--scope", choices=["running", "apps", "installed"], default="running")

    device_select = sub.add_parser("device-select", help="选择设备")
    device_group = device_select.add_mutually_exclusive_group(required=True)
    device_group.add_argument("--id")
    device_group.add_argument("--host")

    mode_set = sub.add_parser("mode-set", help="设置连接模式")
    mode_set.add_argument("--mode", choices=["usb", "remote", "gadget"], required=True)
    mode_set.add_argument("--host")
    mode_set.add_argument("--port", type=int)

    target_set = sub.add_parser("target-set", help="设置目标包名")
    target_set.add_argument("--target", default="")

    for command, help_text in (
        ("run-script-set", "设置 Run 脚本"),
        ("attach-script-set", "设置 Attach 脚本"),
    ):
        script = sub.add_parser(command, help=help_text)
        script.add_argument("--path", required=True)

    extra = sub.add_parser("extra-set", help="设置 Frida 额外参数")
    extra.add_argument("--value", default="")

    for command, help_text in (
        ("adb-force-stop", "ADB 强制停止应用"),
        ("adb-open-app", "ADB 启动应用"),
    ):
        adb = sub.add_parser(command, help=help_text)
        adb.add_argument("--target")

    clear = sub.add_parser("console-clear", help="清空控制台")
    clear.add_argument("--type", choices=["run", "attach"], default="run")

    for command in ("run-log-content", "attach-log-content"):
        add_path_and_limit(sub.add_parser(command, help="读取日志内容"))

    for command in ("run-log-lines", "attach-log-lines"):
        lines = sub.add_parser(command, help="按行读取日志")
        lines.add_argument("--path")
        lines.add_argument("--start", type=int, default=1)
        lines.add_argument("--count", type=int, default=100)

    for command in ("run-log-tail", "attach-log-tail"):
        tail = sub.add_parser(command, help="读取日志尾部或从字节游标增量读取")
        tail.add_argument("--path")
        tail.add_argument("--offset", type=int)
        tail.add_argument("--max-bytes", type=int, default=65536)

    logs = sub.add_parser("logs-list", help="列出当前 IDE 项目中的历史会话日志")
    logs.add_argument("--type", choices=["all", "run", "attach"], default="all")
    logs.add_argument("--limit", type=int, default=50)

    wait_device = sub.add_parser("wait-device", help="等待设备出现，适合 USB/网络抖动恢复")
    wait_group = wait_device.add_mutually_exclusive_group()
    wait_group.add_argument("--id")
    wait_group.add_argument("--host")
    wait_device.add_argument("--type", dest="device_type")
    wait_device.add_argument("--timeout", type=float, default=60.0)
    wait_device.add_argument("--interval", type=float, default=2.0)

    wait_session = sub.add_parser("wait-session", help="等待 Run/Attach 进入 running 或 stopped")
    wait_session.add_argument("--type", choices=["run", "attach"], required=True)
    wait_session.add_argument("--state", choices=["running", "stopped"], required=True)
    wait_session.add_argument("--timeout", type=float, default=30.0)
    wait_session.add_argument("--interval", type=float, default=0.5)
    return parser


def route_command(args: argparse.Namespace) -> Tuple[str, str, Dict[str, str]]:
    routes = {
        "health": ("GET", "/health"),
        "capabilities": ("GET", "/capabilities"),
        "state": ("GET", "/state"),
        "session-status": ("GET", "/session/status"),
        "diagnostics": ("GET", "/diagnostics"),
        "project-current": ("GET", "/project/current"),
        "project-select": ("POST", "/project/select"),
        "project-create": ("POST", "/project/create"),
        "python-env-current": ("GET", "/python-environment/current"),
        "python-env-set": ("POST", "/project/python-environment/set"),
        "python-env-test": ("POST", "/python-environment/test"),
        "devices": ("GET", "/devices"),
        "processes": ("GET", "/processes"),
        "device-select": ("POST", "/device/select"),
        "mode-set": ("POST", "/connection-mode/set"),
        "target-set": ("POST", "/target/set"),
        "run-script-set": ("POST", "/run-script/set"),
        "attach-script-set": ("POST", "/attach-script/set"),
        "extra-set": ("POST", "/extra-args/set"),
        "adb-force-stop": ("POST", "/adb/force-stop"),
        "adb-open-app": ("POST", "/adb/open-app"),
        "run": ("POST", "/run"),
        "stop": ("POST", "/stop"),
        "attach": ("POST", "/attach"),
        "stop-attach": ("POST", "/stop-attach"),
        "console-clear": ("POST", "/console/clear"),
        "run-log-path": ("GET", "/run-log/path"),
        "attach-log-path": ("GET", "/attach-log/path"),
        "run-log-content": ("GET", "/run-log/content"),
        "attach-log-content": ("GET", "/attach-log/content"),
        "run-log-lines": ("GET", "/run-log/lines"),
        "attach-log-lines": ("GET", "/attach-log/lines"),
        "run-log-tail": ("GET", "/run-log/tail"),
        "attach-log-tail": ("GET", "/attach-log/tail"),
        "logs-list": ("GET", "/logs/list"),
    }
    method, endpoint = routes[args.command]
    params: Dict[str, str] = {}
    for source, target in (
        ("name", "name"),
        ("platform", "platform"),
        ("path", "path"),
        ("scope", "scope"),
        ("id", "id"),
        ("host", "host"),
        ("port", "port"),
        ("target", "target"),
        ("value", "value"),
        ("type", "type"),
        ("start", "start"),
        ("count", "count"),
        ("offset", "offset"),
        ("max_bytes", "maxBytes"),
        ("limit", "limit"),
    ):
        if not hasattr(args, source):
            continue
        value = getattr(args, source)
        if value is not None:
            params[target] = str(value)
    if args.command == "mode-set":
        params["mode"] = args.mode
    return method, endpoint, params


def response_data(payload: Dict[str, Any]) -> Dict[str, Any]:
    data = payload.get("data")
    if isinstance(data, dict):
        return data
    return {}


def wait_for_device(common: argparse.Namespace, args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    started = time.monotonic()
    attempts = 0
    last_payload: Dict[str, Any] = {}
    while time.monotonic() - started <= max(0.0, args.timeout):
        attempts += 1
        status, payload = call_api(common.base_url, "/devices", timeout=max(0.1, common.request_timeout))
        last_payload = payload
        if payload.get("ok") is True:
            devices = response_data(payload).get("devices", [])
            for device in devices if isinstance(devices, list) else []:
                if not isinstance(device, dict):
                    continue
                if args.id and device.get("id") != args.id:
                    continue
                if args.host and device.get("host") != args.host:
                    continue
                if args.device_type and str(device.get("type", "")).lower() != args.device_type.lower():
                    continue
                elapsed = int((time.monotonic() - started) * 1000)
                return 200, {
                    "ok": True,
                    "status": 200,
                    "data": {"device": device, "attempts": attempts, "elapsedMs": elapsed},
                }
        elif not payload.get("retryable") and status not in (0, 503, 504):
            return status, payload
        remaining = args.timeout - (time.monotonic() - started)
        if remaining <= 0:
            break
        time.sleep(min(max(0.1, args.interval), remaining))
    return 408, {
        "ok": False,
        "status": 408,
        "errorCode": "WAIT_DEVICE_TIMEOUT",
        "retryable": True,
        "message": f"No matching device appeared within {args.timeout:g}s",
        "data": {"attempts": attempts, "lastResponse": last_payload},
    }


def wait_for_session(common: argparse.Namespace, args: argparse.Namespace) -> Tuple[int, Dict[str, Any]]:
    started = time.monotonic()
    attempts = 0
    last_payload: Dict[str, Any] = {}
    while time.monotonic() - started <= max(0.0, args.timeout):
        attempts += 1
        status, payload = call_api(common.base_url, "/session/status", timeout=max(0.1, common.request_timeout))
        last_payload = payload
        if payload.get("ok") is True:
            session = response_data(payload).get(args.type)
            if isinstance(session, dict) and session.get("state") == args.state:
                elapsed = int((time.monotonic() - started) * 1000)
                return 200, {
                    "ok": True,
                    "status": 200,
                    "data": {"type": args.type, "session": session, "attempts": attempts, "elapsedMs": elapsed},
                }
        elif not payload.get("retryable") and status not in (0, 503, 504):
            return status, payload
        remaining = args.timeout - (time.monotonic() - started)
        if remaining <= 0:
            break
        time.sleep(min(max(0.1, args.interval), remaining))
    return 408, {
        "ok": False,
        "status": 408,
        "errorCode": "WAIT_SESSION_TIMEOUT",
        "retryable": True,
        "message": f"{args.type} did not reach {args.state} within {args.timeout:g}s",
        "data": {"attempts": attempts, "lastResponse": last_payload},
    }


def parse_common_args(argv: list[str]) -> Tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--base-url", default=os.environ.get("ZAFRIDA_API_BASE", DEFAULT_BASE_URL))
    parser.add_argument("--request-timeout", type=float, default=DEFAULT_REQUEST_TIMEOUT)
    parser.add_argument("--retries", type=int, default=0)
    parser.add_argument("--retry-delay", type=float, default=1.0)
    parser.add_argument("--compact", action="store_true")
    return parser.parse_known_args(argv)


def main() -> int:
    common, remaining = parse_common_args(sys.argv[1:])
    parser = build_command_parser()
    args = parser.parse_args(remaining)

    if args.command == "wait-device":
        status, payload = wait_for_device(common, args)
    elif args.command == "wait-session":
        status, payload = wait_for_session(common, args)
    else:
        method, endpoint, params = route_command(args)
        status, payload = call_api(
            common.base_url,
            endpoint,
            method,
            params,
            timeout=max(0.1, common.request_timeout),
            retries=max(0, common.retries),
            retry_delay=max(0.0, common.retry_delay),
        )

    print_json(payload, common.compact)
    if status < 200 or status >= 300 or payload.get("ok") is not True:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
