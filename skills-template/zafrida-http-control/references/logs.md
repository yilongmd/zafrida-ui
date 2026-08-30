# 读取 ZAFrida 日志

持久化的 Run/Attach 日志是判断进程启动、TypeScript 编译、agent 异常、传输断开和退出码的主要证据。只有没有日志文件时才退回 Console 文本。

把 API 返回的日志当作原始诊断证据。分析前不得脱敏、归一化、去重或改写路径、包名、命令参数、agent 输出和堆栈。回答时只引用必要片段，但必须保留影响 Frida 行为的原始值。

## 选择日志来源

1. 调用 `session-status` 或 `state`，确认 Run/Attach 类型和当前路径。
2. 没有当前路径或 IDE 已重启时，调用：

```bash
python3 <skill-dir>/scripts/zafrida_api.py logs-list --type all --limit 50
```

3. 只把返回路径用于 ZAFrida 日志命令。API 会拒绝当前 IDE 项目的 ZAFrida 日志目录之外的路径。

## 默认方式：tail 与游标

读取近期输出，不加载整个文件：

```bash
python3 <skill-dir>/scripts/zafrida_api.py run-log-tail --max-bytes 65536
```

响应包含字节级 `startOffset`、`nextOffset`、`fileSize` 和 `hasMore`。保存 `nextOffset`，按游标增量读取：

```bash
python3 <skill-dir>/scripts/zafrida_api.py run-log-tail --offset <nextOffset> --max-bytes 65536
```

`reset` 为 true 时，文件已缩短或替换，应丢弃旧游标，把返回内容当作新流。会话停止且连续两次读取的 `nextOffset` 相同时停止轮询。Attach 使用 `attach-log-tail`；读取 `logs-list` 的历史条目时传入 `--path`。

## 其他读取方式

- `*-log-content --max-bytes N`：获取一次尾部快照；省略限制时仍受服务端硬上限约束。
- `*-log-lines --start N --count M`：面向人工的行分页，每次最多 2000 行；它会从头扫描，活动大日志优先字节游标。
- `*-log-path`：只获取路径和元数据。

## 解释输出

- `[ZAFrida] Command:`：实际 CLI、环境和设备参数。
- `[ZAFrida] Log file:`：日志持久化路径。
- `[ZAFrida] Process terminated (exitCode=...)`：进程终态。
- `Failed to load script`、`compilation failed` 或 unresolved imports：优先检查 TypeScript/工程结构，不要误判为设备传输问题。
- Frida 17 中涉及已移除 `Module.*`、`Memory.*` 静态方法的 `TypeError`：属于 API 迁移问题。
- `unable to find process`：优先检查目标和 app 生命周期。
- `unable to connect`、`transport is closed`、设备断开文本：属于可恢复链路证据。
- agent 的 `console.log` 不保证带 ZAFrida 前缀，不能当作噪声丢弃。

总结日志时同时给出路径和 offsets。不能只因为修改 API 返回 accepted 就声称 Run/Attach 成功。
