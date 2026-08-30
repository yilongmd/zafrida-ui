# Reading ZAFrida logs

The persisted Run and Attach logs are the primary evidence for process startup, TypeScript compilation, agent exceptions, transport loss, and exit codes. Console text is only a fallback when no log file exists.

## Choose the source

1. Call `session-status` or `state` to identify Run versus Attach and the current path.
2. If there is no current path or the IDE restarted, call:

```bash
python3 <skill-dir>/scripts/zafrida_api.py logs-list --type all --limit 50
```

3. Use the returned path only with ZAFrida log commands. The API intentionally rejects paths outside this IDE project's ZAFrida log directories.

## Default: tail and cursor

Read recent output without loading the whole file:

```bash
python3 <skill-dir>/scripts/zafrida_api.py run-log-tail --max-bytes 65536
```

The response provides byte-based `startOffset`, `nextOffset`, `fileSize`, and `hasMore`. Preserve `nextOffset` and poll incrementally:

```bash
python3 <skill-dir>/scripts/zafrida_api.py run-log-tail --offset <nextOffset> --max-bytes 65536
```

If `reset` is true, the file shrank or was replaced; discard the old cursor and process the returned content as a new stream. Stop polling when the session is stopped and two consecutive reads have the same `nextOffset`.

Use `attach-log-tail` for Attach. Supply `--path` to inspect an entry from `logs-list`.

## Other reading modes

- `*-log-content --max-bytes N`: one tail snapshot. Omitting a limit is allowed only up to the server's hard response limit.
- `*-log-lines --start N --count M`: human-oriented paging, at most 2000 lines per call. It rescans from the beginning, so prefer byte cursors for actively growing or large logs.
- `*-log-path`: metadata only.

## Interpret output

- `[ZAFrida] Command:` identifies the exact CLI and selected environment/device arguments.
- `[ZAFrida] Log file:` identifies persistence setup.
- `[ZAFrida] Process terminated (exitCode=...)` is the terminal process state.
- `Failed to load script`, `compilation failed`, or unresolved imports point to TypeScript/project scaffolding, not device transport.
- `TypeError` involving removed `Module.*` or `Memory.*` static methods points to Frida 17 API migration.
- `unable to find process` points to target selection or app lifecycle.
- `unable to connect`, `transport is closed`, or device-disconnected text is retryable discovery/recovery evidence.
- Agent `console.log` output has no guaranteed ZAFrida prefix; do not discard it as noise.

Always quote or summarize the relevant log segment with its path and offsets. Do not claim the Run/Attach succeeded solely because the HTTP mutation was accepted.
