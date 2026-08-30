---
name: zafrida-http-control
description: Control and diagnose the local ZAFrida JetBrains plugin through its loopback HTTP API. Use for ZAFrida project/environment setup, Frida device and process discovery, Run/Attach lifecycle control, unstable-device recovery, or incremental session-log inspection. Do not use merely to explain or edit ordinary Frida scripts when no running ZAFrida instance is involved.
---

# ZAFrida HTTP control

Use the bundled `scripts/zafrida_api.py` relative to this `SKILL.md`. Do not assume that it was copied to `~/.claude/tools` or another global path.

## Establish context

Start with these read-only calls:

```bash
python3 <skill-dir>/scripts/zafrida_api.py health
python3 <skill-dir>/scripts/zafrida_api.py capabilities
python3 <skill-dir>/scripts/zafrida_api.py state
```

If the API is unreachable, ask the user to open the ZAFrida ToolWindow and enable `Settings/Preferences → ZAFrida → Skills HTTP API`. The default base URL is `http://127.0.0.1:17839/zafrida/api/v1`; `ZAFRIDA_API_BASE` or `--base-url` may override it.

Treat returned `errorCode` and `retryable` as authoritative. A successful mutation with `accepted: true` means the UI accepted the request, not that the Frida process has already reached a running state; confirm with `wait-session` and then inspect the log.

## Safety and retry boundary

- Automatically retry only read-only discovery/status/log operations, using bounded backoff.
- Never automatically replay `run`, `attach`, `project-create`, `adb-open-app`, or another externally mutating action. Check current state before deciding whether a second invocation is needed.
- `stop` and `stop-attach` are safe cleanup operations, but report when no session was running.
- Stop recovery when the configured timeout expires. Return the last structured error instead of looping indefinitely.
- Do not replace a project's Python environment, target, script, device, or connection mode unless the user requested that change or it is necessary for the requested ZAFrida operation.

## Route by task

- For projects, Python environments, connection settings, scripts, and session control, read [references/operations.md](references/operations.md).
- For USB/network instability, Frida server mismatch, stale processes, and bounded recovery, read [references/recovery.md](references/recovery.md).
- Whenever the task involves a failed Run/Attach, agent output, or “read the logs,” read [references/logs.md](references/logs.md) before choosing a log command.

## Default execution shape

1. Read `state`; select a project only if the requested one is not active.
2. Read `python-env-current`; use `python-env-test` before a run when the environment changed or its Frida version is uncertain.
3. Use `wait-device` for an unstable phone, then select the matched device and query `processes` when needed.
4. Set only missing or explicitly requested fields.
5. Invoke `run` or `attach` once, then `wait-session` for `running`.
6. Read the matching `*-log-tail`. Preserve `nextOffset` for incremental polling.
7. On failure, classify the log/error first; recover using the narrowest relevant action.

All commands emit one JSON object and return a non-zero process exit code when `ok` is false.
