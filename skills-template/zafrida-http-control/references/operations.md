# ZAFrida operations

Run commands as:

```bash
python3 <skill-dir>/scripts/zafrida_api.py <command> [arguments]
```

Common flags may appear before or after the command:

- `--base-url URL`: override the API base URL.
- `--request-timeout SECONDS`: per-request timeout, default 30.
- `--retries N --retry-delay SECONDS`: bounded retries for safe operations only.
- `--compact`: compact JSON output.

## Read-only context

| Command | Purpose |
|---|---|
| `health` | Server reachability, bound port, and RunPanel readiness. |
| `capabilities` | Supported features, script extensions, retry classes, and response limits. |
| `state` | Active project, UI fields, selected device, sessions, and current log metadata. |
| `session-status` | Lightweight Run and Attach state for polling. |
| `diagnostics` | Python, Frida tools/version, device connectivity, and ADB checks. |
| `project-current` | Active project plus registered projects and current config. |
| `python-env-current` | Effective interpreter, environment root, source, PATH entries, and resolved tools. |

## Project and Python environment

```bash
python3 <skill-dir>/scripts/zafrida_api.py project-select --name demo
python3 <skill-dir>/scripts/zafrida_api.py project-create --name demo --platform android

# Environment root or interpreter file; projects may share the same path.
python3 <skill-dir>/scripts/zafrida_api.py python-env-set --path /abs/path/to/venv
python3 <skill-dir>/scripts/zafrida_api.py python-env-test --path /abs/path/to/venv

# Clear the override and return to the PyCharm project interpreter.
python3 <skill-dir>/scripts/zafrida_api.py python-env-set --path ""
python3 <skill-dir>/scripts/zafrida_api.py python-env-test
```

Supported local layouts include system/pyenv, venv/virtualenv, Conda, uv, Poetry, Pipenv, and Hatch. Remote SSH/Docker/WSL SDKs cannot launch local Frida processes. Both the resolved IDE environment and an explicit project environment are authoritative: missing `frida`, `frida-ps`, or `frida-ls-devices` is an error, never a reason to silently use another Frida version.

## Device, process, and connection

```bash
python3 <skill-dir>/scripts/zafrida_api.py devices --retries 2
python3 <skill-dir>/scripts/zafrida_api.py wait-device --type usb --timeout 60 --interval 2
python3 <skill-dir>/scripts/zafrida_api.py device-select --id <returned-device-id>
python3 <skill-dir>/scripts/zafrida_api.py device-select --host 127.0.0.1:14725
python3 <skill-dir>/scripts/zafrida_api.py mode-set --mode usb
python3 <skill-dir>/scripts/zafrida_api.py mode-set --mode remote --host 127.0.0.1 --port 14725
python3 <skill-dir>/scripts/zafrida_api.py processes --scope running
python3 <skill-dir>/scripts/zafrida_api.py processes --scope apps
python3 <skill-dir>/scripts/zafrida_api.py processes --scope installed
```

`wait-device` matches any device if no `--id`, `--host`, or `--type` is supplied. Use `--type usb` when the concrete USB ID is not known. A listed synthetic remote/gadget entry only describes a configured endpoint; query `processes` to prove connectivity.

## Scripts and run settings

Both `.js` and `.ts` paths are accepted. Frida 17's frida-tools REPL compiles `.ts` loaded with `-l` and bundles the standard Java/ObjC bridges for compatibility. Use precompiled JavaScript with Frida 16; npm or third-party module imports still require a valid TypeScript scaffold/build.

```bash
python3 <skill-dir>/scripts/zafrida_api.py target-set --target com.example.app
python3 <skill-dir>/scripts/zafrida_api.py run-script-set --path /abs/path/agent.ts
python3 <skill-dir>/scripts/zafrida_api.py attach-script-set --path /abs/path/attach.js
python3 <skill-dir>/scripts/zafrida_api.py extra-set --value=--realm=emulated
```

The primary script is always loaded first. Frida CLI accepts repeated `-l/--load` options, so an advanced workflow may add one or more extra scripts through `extra-set`, for example `--value='-l /abs/path/extra.js -l /abs/path/trace.js'`. Preserve load order and quote paths containing spaces. Prefer a single entry script with imports when scripts share state or have ordering dependencies.

## Session lifecycle

```bash
python3 <skill-dir>/scripts/zafrida_api.py run
python3 <skill-dir>/scripts/zafrida_api.py wait-session --type run --state running --timeout 15
python3 <skill-dir>/scripts/zafrida_api.py stop

python3 <skill-dir>/scripts/zafrida_api.py attach
python3 <skill-dir>/scripts/zafrida_api.py wait-session --type attach --state running --timeout 15
python3 <skill-dir>/scripts/zafrida_api.py stop-attach
```

Do not infer success from `accepted: true`. If `wait-session` reaches `stopped` immediately, inspect the corresponding log tail for startup, compiler, target, or transport errors.

## ADB and console

```bash
python3 <skill-dir>/scripts/zafrida_api.py adb-force-stop
python3 <skill-dir>/scripts/zafrida_api.py adb-open-app --target com.example.app
python3 <skill-dir>/scripts/zafrida_api.py console-clear --type run
```

ADB actions are asynchronous in the current API. Their response confirms acceptance, not device-side completion; verify through `processes`, `wait-device`, or logs.
