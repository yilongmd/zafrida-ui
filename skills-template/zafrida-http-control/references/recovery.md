# Recovering unstable devices

Use bounded recovery. Preserve the user's selected project, environment, target, and scripts unless the evidence shows one is wrong.

## Retry classification

Safe to retry automatically:

- `health`, `capabilities`, `state`, `session-status`
- `devices`, `processes`
- `project-current`, `python-env-current`
- log path/list/content/lines/tail reads

Do not automatically replay:

- `run` or `attach`: a delayed first request may already have started a process.
- `project-create`: retries may collide with an already-created directory.
- `adb-open-app`: it changes device state.
- project/environment/script/target setters unless the requested value is still absent.

## USB recovery sequence

1. Call `health`, then `state`.
2. Call `wait-device --type usb --timeout 60 --interval 2`, or use a concrete device ID when known.
3. Call `device-select` with the returned ID.
4. Call `processes --scope apps`. This distinguishes “enumeration sees a device” from “frida-server is usable.”
5. If process listing fails, call `diagnostics` once and inspect `errorCode`:
   - `FRIDA_COMMAND_TIMEOUT` or `FRIDA_DEVICE_UNAVAILABLE`: retry read-only discovery with backoff.
   - `PYTHON_ENVIRONMENT_INVALID`: stop retrying and repair/select the environment.
   - `FRIDA_COMMAND_FAILED`: read stderr/logs; repeated blind retries are unlikely to help.

ADB and Frida are separate paths. `adb devices` working does not prove that `frida-server` is running or version-compatible. Conversely, a remote Frida endpoint may work without an ADB device.

## Remote or Gadget recovery

1. Confirm `mode-set` state and exact `host:port` through `state`.
2. For loopback Android forwarding, verify ADB availability through `diagnostics`.
3. Call `processes`; a synthetic Remote/Gadget entry in `devices` is configuration, not a connectivity guarantee.
4. On transport closure, wait briefly and retry `processes`; do not replay a Run/Attach until `session-status` proves it is stopped.

## Target/process recovery

- “unable to find process” or an immediate Attach exit: refresh `processes --scope apps`, then set the exact identifier.
- Spawn target not installed: use `processes --scope installed` before changing the target.
- A stale running app: with user authorization, call `adb-force-stop`, verify it disappeared, then start once.
- Version mismatch: compare `python-env-test`'s Frida version with the device's `frida-server`; select the intended shared Frida 16/17 environment rather than changing global PATH.

After the timeout, return the last JSON response and the commands already attempted. Never continue an unbounded recovery loop.
