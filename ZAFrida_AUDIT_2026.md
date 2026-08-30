# ZAFrida 全量审计与演进建议（2026）

审计范围：插件架构、线程与生命周期、ZAFrida Project/Python 环境、Frida CLI、Frida 17/TypeScript、Run/Attach、ADB、模板、日志、ToolWindow UI、本地 HTTP API、Skill/CLI、MCP、构建与测试。

状态标记：

- `已处理`：本轮工作树中已完成并通过自动测试。
- `下一阶段`：会影响稳定性，建议优先进入后续开发。
- `增强项`：不是当前缺陷，但会显著提升“比命令行更方便”或 AI 可编排能力。

## 1. 总体结论

ZAFrida 的核心产品方向是成立的：项目上下文、设备/目标、Run/Attach、模板和持久日志组合起来，确实比反复手写命令行更适合长期逆向工作。现状的主要问题不是功能不可用，而是去年版本留下的三类技术债：

1. UI 状态与后台任务耦合较重，切项目、刷新设备、启动会话时存在竞态或 EDT 阻塞风险。
2. AI 接口最初只是“把 UI 按钮映射成 HTTP/MCP”，缺少能力发现、结果确认、恢复策略和增量日志语义。
3. Frida 版本被当成一个全局值，而现在实际使用方式是多个项目共享或切换多套 Frida 16/17 Python 环境。

本轮已把项目从“全局版本 + JS-only + 薄 HTTP/MCP”推进到“每项目环境 + JS/TS + 可恢复 Skill + 受限日志 API”。剩余工作应优先围绕操作结果模型、UI 线程隔离和真实设备集成测试，而不是继续堆按钮。

## 2. Frida 17 / TypeScript 支持结论

| 能力 | 审计前 | 本轮后 | 说明 |
|---|---:|---:|---|
| `frida -l agent.ts` | 插件 UI 拒绝 `.ts` | Frida 17 支持 | 文件选择器、右键 Run/Attach、Snippets 与 API 均接受 `.ts`；Frida 16 项目应先用 `frida-compile` 生成 JS。 |
| Frida Compiler | 未验证 | 已验证 | 本机 Frida 16.1.4 / frida-tools 12.3.0 与 Frida 17.9.1 / frida-tools 14.8.2 均成功编译同一 smoke fixture。 |
| Frida 17 Module API | 部分模板运行失败 | 已处理已知用法 | 内置 Native/iOS 模板迁移到 module instance 与 global export 新 API。 |
| Frida 17 Memory API | 部分 iOS 模板运行失败 | 已处理已知用法 | 静态 `Memory.read*/write*` 改为 `NativePointer` 方法。 |
| Java/ObjC/Swift bridge | 容易误判 | CLI 简单脚本兼容 | ZAFrida 使用 frida-tools REPL；Frida 17 的 REPL 为兼容性携带 bridges。带 `import` 的 TS 工程仍需 npm/scaffold。 |
| IDE 完整 typings/npm 工程 | 文档曾声称“一键安装”，实际没有入口 | 明确不再虚假声明 | 后续应做正式 TypeScript Setup，而不是继续维护一份残缺 `d.ts`。 |
| 自定义旧脚本自动迁移 | 不完整 | 保持保守 | 只转换新插入内容，不重写用户已有脚本；旧脚本迁移应提供显式检查/预览。 |

官方依据：

- Frida 17 发布说明：https://frida.re/news/2025/05/17/frida-17-0-0-released/
- Frida bridges 与 REPL 自动编译：https://frida.re/docs/bridges/
- Frida JavaScript/TypeScript API：https://frida.re/docs/javascript-api/

## 3. 本轮已处理的稳定性问题

### 3.1 生命周期、线程和状态竞态

1. `已处理` ToolWindow 主面板未绑定 Content disposer，可能遗留 Console、MessageBus 订阅和 API RunPanel 引用。
2. `已处理` 快速切换 ZAFrida Project 时，旧的异步配置结果可能覆盖新项目 UI。
3. `已处理` 多次刷新设备时，较慢的旧请求可能覆盖较新的设备列表。
4. `已处理` Project Settings 刷新 target 时，旧 scope/device 请求可能覆盖新选择。
5. `已处理` Project Settings 保存任务曾在后台线程读取 Swing radio 状态。
6. `已处理` 停止会话会在 EDT 等待日志 writer；现在停止流程在后台完成。
7. `已处理` 进程终止 listener 曾直接从进程线程修改 Swing 按钮状态。
8. `已处理` 模板初始化、刷新、自定义模板新增/删除从 EDT 移到后台；面板复用正式 Project Service，不再 `new` 第二个实例。
9. `已处理` ToolWindow 被释放后，模板/设备异步回调不再更新已释放组件。

### 3.2 会话与日志

1. `已处理` 启动会话曾构建两次 Frida command line，环境切换时可能出现显示命令与实际命令不一致。
2. `已处理` 日志 writer 创建后若进程创建失败，会遗留线程/文件句柄。
3. `已处理` 极短进程可能在 `sessions.put()` 前结束，留下终止但未清理的 session。
4. `已处理` 日志队列原先无界且每个输出 chunk 都 flush；现在有界、批量 flush，拥塞时写入明确 dropped marker。
5. `已处理` 同秒重启可能复用旧日志并追加；现在文件名含毫秒并处理碰撞。
6. `已处理` 日志目录可配置为绝对路径或 `../` 越界；现在只允许项目内相对目录，否则安全回退。
7. `已处理` 会话日志增加开始时间和脱敏后的 command header；`token/password/secret/api-key` 不写明文。
8. `已处理` 日志 API 增加历史列表和 UTF-8 边界安全的 byte cursor tail。
9. `已处理` 超大日志不再默认 `readAllBytes()`；服务端有 4 MiB 单响应硬限制。
10. `已处理` 日志 API 不再无条件从 EDT 复制整个 Console；仅在无磁盘日志时读取有界尾部并返回截断标记。
11. `已处理` Stop 不再抢先关闭日志 writer；终止回调可写完最后输出和 exit code，项目释放时再兜底关闭残留 writer。

### 3.3 配置与项目安全

1. `已处理` `zafrida*.xml` 解析器可接受 DOCTYPE/external entity；现在使用平台安全 JDOM 入口并有 XXE 测试。
2. `已处理` workspace 可登记 `../outside` 或绝对目录；现在过滤路径穿越。
3. `已处理` workspace 中重名/重复目录会产生不一致映射；现在忽略重复项并记录日志。
4. `已处理` New Project 可能复用现有目录并覆盖配置；现在重名或目录已存在会明确失败。
5. `已处理` 注册外部已有项目时，同名项目可能替换原项目；现在拒绝冲突。
6. `已处理` 选择 Remote/Gadget 曾清除上次 USB serial，导致 ADB forward/force-stop 在多设备下失去目标；现在分别保留 host 与 USB ID。
7. `已处理` ADB forward 以前永远不带 `-s <serial>`；现在可使用项目保存的具体设备 ID。
8. `已处理` 当前 IDE Python 环境缺少 Frida 工具时曾可能落到系统 PATH，造成 Frida 16/17 静默串用；现在 IDE 环境与显式项目环境均为权威来源。
9. `已处理` 脚本字段可通过绝对路径或 `..` 指向项目外，workspace 规范化别名也可绕过重复检测；现在统一规范化并限制为安全相对路径。
10. `已处理` 项目名 `.` 可能把配置写入平台根目录；Manager 入口现在明确拒绝 `.` / `..`。
11. `已处理` 旧全局配置中的 null/空工具路径、非法端口和重复 remote host 未统一归一化；载入边界现在补默认值、范围检查与去重。

### 3.4 UI 与编辑器行为

1. `已处理` 项目搜索框在输入过滤文字时会自动触发项目切换。
2. `已处理` 切换到主/附加脚本缺失的项目时，会继续保留上一个项目脚本并可能误运行。
3. `已处理` Snippets 在任意可写文件（包括 Java/Python）中都显示；现在只在 `.js/.ts` 中显示。
4. `已处理` Run/Attach 右键动作只认 `.js`；现在支持 `.js/.ts`，并在无关文件中隐藏。
5. `已处理` 项目平台传给 Templates 后没有任何效果；现在 Android/iOS 项目会切到对应内置分类，同时保留 Favorites/Custom 用户选择。
6. `已处理` Attach PID model 已存在但从未使用；数值 target 现在走 `-p <pid>`，普通 target 继续走 `-N <name>`。
7. `已处理` 全局显示的 Frida Version 容易被误解为当前项目版本；现在标为 fallback，当前项目环境探测结果优先。
8. `已处理` 插件自己请求 Marketplace 检查更新，重复 IDE 能力且接口参数不可靠；已删除，交给 JetBrains Plugins 管理。
9. `已处理` 新增同名自定义模板会静默覆盖旧文件；现在使用原子创建，名称冲突明确失败并保留原模板。
10. `已处理` Settings 页手动 Start/Stop API 会在 Apply 前直接改持久化 state，Cancel 也无法撤销；现在手动控制只使用临时 UI 端口，配置仅由 Apply/OK 保存。

### 3.5 API / AI

1. `已处理` 日志接口接受任意绝对路径，可读取本机任意文件。
2. `已处理` API 返回 `Access-Control-Allow-Origin: *`，恶意网页可尝试调用本机插件；现在拒绝非 loopback Browser Origin。
3. `已处理` POST body 无大小限制；现在限制 64 KiB。
4. `已处理` 错误只有 message；现在追加稳定的 `errorCode` 与 `retryable`，保留原字段兼容旧客户端。
5. `已处理` Frida timeout 与普通 exit 混在一起；现在返回 `FRIDA_COMMAND_TIMEOUT`，设备/transport 类错误返回 `FRIDA_DEVICE_UNAVAILABLE`。
6. `已处理` `/devices` 与 UI combo 来源不一致，AI 能看到设备却无法 `/device/select`；现在统一包含配置的 remote/gadget，并可把新发现设备加入 UI。
7. `已处理` 增加 `/capabilities`、Python 环境 current/set/test、`/session/status`、`/logs/list`、Run/Attach log tail，共 35 个端点。
8. `已处理` Skill 新增 `wait-device`、`wait-session`、有界 backoff、日志 cursor 和恢复决策；副作用操作不会自动重放。
9. `已处理` UI mutation 原先可能先超时、后在 EDT 迟到执行；现在同步跨模态执行并返回，避免 AI 因假失败重放副作用。
10. `已处理` 本地 API 改为有界线程池，并拒绝 context 前缀误匹配、畸形百分号编码和过大的请求体。

### 3.6 老代码清理

1. `已处理` 删除未注册/无调用的旧 Project Configurable 与旧 Project state。
2. `已处理` 删除第二套、未使用且 Marker 不同的 Template manipulator/skeleton。
3. `已处理` 删除未使用的旧 ToolWindow panel、process renderer 和无入口的残缺 typings installer。
4. `已处理` `ZaStrUtil` 从约 3300 行/数百方法收缩到项目实际使用的 5 项能力。
5. `已处理` 移除生产源码不使用的 Kotlin JVM plugin/stdlib 配置，保留 Gradle Kotlin DSL。
6. `已处理` 迁移 `Project.getBaseDir()`、旧 Modality/JDOM API；Java lint 当前无 deprecated/unchecked 警告。
7. `已处理` 修正 Marketplace vendor URL。

## 4. 下一阶段应优先处理的问题

### P1：直接影响稳定性或 AI 对结果的判断

1. `下一阶段` **Run/Attach 进程创建仍可能发生在 EDT。** 环境解析、日志创建和 OS process 启动应拆成 prepare/background + attach/start-on-EDT 的明确阶段，并增加 `STARTING` 状态。
2. `下一阶段` **HTTP API 是 Project Service，却使用一个全局固定端口。** 同时打开多个 IDE Project 时只有一个能绑定，当前 Settings 还会尝试启动全部。建议改为 Application 级 server + project routing，或显式选择 owner project。
3. `下一阶段` **副作用 API 缺少 operation ID。** `/run`、`/attach`、ADB 当前只返回 accepted；应有 `operationId/state/error/startedAt/completedAt`，支持幂等键与结果查询。
4. `下一阶段` **ADB force-stop/open-app API 不返回最终结果。** 应把 AdbService 暴露为 future/result，而不是回调接受后立即 200。
5. `下一阶段` **终止后的 session 状态只存在日志。** `/session/status` 应保留 last exit code、结束时间、失败阶段和最近错误，避免 AI 只能等超时。
6. `下一阶段` **ConsoleView 本身仍可无限增长。** 持久日志队列已限流，但长时间高频 Hook 仍可能耗尽 IDE 内存；应使用平台支持的 cyclic buffer 或可配置输出上限。
7. `下一阶段` **损坏的 project/workspace XML 会降级为默认配置。** 后续保存可能覆盖损坏文件；应先备份 `.broken-<timestamp>`，在 UI/Notification 明确提示，再决定是否重建。
8. `下一阶段` **模板 Marker 对重复块、缺失 end marker、部分手工注释的恢复不够严格。** 应抽取单一 parser/manipulator，并为历史脚本建立 round-trip 测试。
9. `下一阶段` **API 单类已超过合理边界。** 拆为 server/security、project/environment、device/session、log reader、JSON response；端点 schema 应成为单一数据源。
10. `下一阶段` **缺少真实 IDE/API/设备集成测试。** 单元测试无法证明 Console attach、ToolWindow disposal、USB 抖动、Frida server mismatch、Windows console fallback。
11. `下一阶段` **loopback API 无 bearer token。** Browser Origin 与路径边界已修复，但任何本机进程仍可调用；可增加默认随机 token，并允许 Skill 从受限配置文件读取。
12. `下一阶段` **ADB forward 失败后仍继续启动 Frida。** 应区分“已有 forward 可继续”和“明确不可达必须中止”，把策略和结果写入 operation state。
13. `下一阶段` **Trace Log 增量同步只比较文件大小。** 同大小内容变化会漏同步；staging 文件名也可能在并发任务中碰撞。建议 size+mtime/hash、唯一 staging 子目录和 finally cleanup。
14. `下一阶段` **创建项目涉及目录、project XML、脚本和 workspace XML 多步写入，但不是事务。** 中途失败会留下半成品目录或内存/workspace 不一致；应增加可恢复 journal 或明确的补偿清理与启动修复。
15. `下一阶段` **部分字段 setter 先更新 UI、再异步排队保存配置，却立即返回 200。** 应让 target/extra/script/device setter 返回 `persisted` 或等待 config revision，避免 AI 紧接着切项目时丢失更新。

### P2：架构与功能扩展

1. `增强项` 用 IntelliJ RunConfiguration/Execution API 表达 ZAFrida Run/Attach，而不只是在 ToolWindow 内维护进程；可获得原生 rerun、stop、历史和状态呈现。
2. `增强项` Python 环境增加 workspace 级命名 profile/alias（例如 `frida16`、`frida17`），项目保存 profile ID + resolved path；当前“从其他项目复用路径”的方式可用但不够可迁移。
3. `增强项` 环境 profile 增加只读 fingerprint：Python 版本、frida、frida-tools、平台、最后验证时间；切换时无需重复猜测。
4. `增强项` Remote 配置结构化支持 Frida 新参数：TLS certificate、token、Origin、keepalive、device options、realm/runtime，而不是都塞进 Extra。
5. `增强项` 支持多个 `-l` 脚本、parameters JSON、CModule、`--runtime=qjs/v8` 与可复用 preset。
6. `增强项` 设备健康状态区分：枚举可见、server 可连接、版本匹配、目标可访问、ADB 可用；不要只用一个 device combo 表达全部状态。
7. `增强项` 支持显式“底层 ADB device”字段，Remote/Gadget loopback 与 USB serial 不再隐式复用 lastDeviceId。
8. `增强项` 为 Frida 17 提供 TypeScript Setup：调用/复用 `frida-create -t agent`，预览将创建的 `package.json/tsconfig`，不覆盖已有工程。
9. `增强项` 增加旧脚本兼容检查器：只报告 Frida 17 移除 API，提供 diff/quick-fix，禁止静默重写整个用户脚本。
10. `增强项` 模板元数据显式声明平台、最低/最高 Frida 版本、是否需要 bridge/依赖、风险级别，不再只靠目录和两行注释。
11. `增强项` built-in 模板升级采用版本/hash 策略；现在每个新 service 实例会刷新内置副本，用户只能在 Custom 中安全修改。
12. `增强项` Favorites、splitter 比例、Console 搜索选项和最近日志选择应持久化。
13. `增强项` `ZaFridaRunPanel`（约 1800 行）和 `ZaFridaTemplatePanel`（约 900 行）仍同时承担 view、状态机和编排；应拆出 Session/Device/Template coordinator 与可测试状态模型，避免继续形成 UI 上帝类。

## 5. UI 专项审计

### 现有优点

- Project/Device/Run Script/Attach Script/Target/Extra 的主任务路径清楚。
- Run 与 Attach 分离、双 Console、脚本定位、模板预览都是命令行不具备的有效价值。
- Project Settings 把目标选择、连接模式和 Python 环境放在同一上下文，方向正确。

### 主要 UI 问题

1. `已处理` 删除 Header 中重复的 Run/Stop/ADB 操作行，仅保留 Session 面板内的一套操作；删除前状态已由独立 Git 提交保留，可按需恢复。
2. `下一阶段` 设备刷新只有禁用按钮和 Console 文本，没有就地 spinner、耗时、取消或 retry 状态。
3. `部分处理` ToolWindow 标题显示插件版本，Project 行显示当前 Frida 版本；后续可补 Python 环境类型并支持点击进入设置/诊断。
4. `部分处理` Run/Attach Console 标签显示 `Idle/Running/Stopping`；`Starting/Failed(exit)` 仍需会话服务保留启动阶段和终态。
5. `下一阶段` 脚本绝对路径在窄面板中难读；应显示项目相对路径，完整路径放 tooltip，并标明 `JS/TS`。
6. `下一阶段` Project Settings 的 Python 路径输入、三个按钮和 target 区在小窗口容易横向拥挤；建议分为 Environment / Connection / Target 三段。
7. `下一阶段` Console 顶部同时放路径、搜索和 4 个 icon-only 按钮；应增加历史日志下拉、Follow 开关、暂停输出、复制诊断包。
8. `下一阶段` 日志与 Console 缺少 stdout/stderr/ZAFrida metadata/agent message 的过滤和颜色语义。
9. `下一阶段` Templates 三栏在窄 ToolWindow 可用性差；可在窄宽度自动变成列表+抽屉预览。
10. `下一阶段` Favorites 未持久化；模板刷新/新增/删除需要统一 busy/error empty state。
11. `下一阶段` 全 UI 混用英语、少量中英双语诊断和旧 “JS” 名称；应使用 IntelliJ resource bundle 做 i18n，不再硬编码。
12. `下一阶段` icon-only 按钮虽有 tooltip，但缺少可访问名称/键盘导航统一检查。
13. `下一阶段` Windows/Linux 的默认 `Ctrl+Alt+S` 与 JetBrains Settings 快捷键冲突；不应继续抢占平台快捷键，建议移除默认绑定并让用户在 Keymap 中选择。
14. `增强项` 增加“复制 AI 诊断上下文”：capabilities/state/diagnostics/session/log tail 自动脱敏后一次复制。
15. `增强项` 增加日志时间线：环境选择 → 设备恢复 → 命令启动 → script load → transport/exit，AI 和人都更容易定位阶段。

## 6. AI/API/日志后续可开放的方法

当前 Skill 已覆盖：health/capabilities/state、项目、Python 环境、设备/进程、连接模式、脚本/参数、Run/Attach/Stop、ADB、诊断、Console、历史日志和 cursor tail。

建议下一阶段增加：

1. `operation/start|get|cancel`：统一长操作状态，取代 accepted-only。
2. `session/history`：最近会话、exit code、命令、环境 fingerprint、日志和失败阶段。
3. `events`（SSE 或 long-poll）：设备变化、session 状态、日志增长；减少 AI 高频轮询。
4. `device/probe`：一次返回 Frida/ADB/server/version/latency 的结构化健康结果。
5. `device/wait` 服务端原语：CLI 已有确定性 wait，其他客户端也可复用。
6. `project/environment-profiles`：命名、验证、共享和引用环境。
7. `templates/list|preview|toggle`：复用现有 Marker 逻辑，让 AI 组合模板但不直接改协议块。
8. `trace-logs/pull|status|list|tail`：把 Tools tab 的 Android trace 同步正式开放。
9. `script/compatibility-check`：报告 Frida 17 移除 API、bridge/import 缺失和 TypeScript compile diagnostics。
10. `diagnostic-bundle`：结构化导出 state、环境、最近错误和限定大小日志，不包含 token/敏感参数。

所有新增 mutation 都应具备幂等键、明确授权边界、operation 状态和停止条件；不要开放任意 shell command。

## 7. MCP 去留决策

### 当前判断

MCP server 不承载 ZAFrida 独有能力，只是手写 27 个 schema，再同步调用同一个 HTTP API。它目前有四个明显成本：

1. 与 Skill CLI/API 三份路由重复，新增端点必然漂移。
2. async MCP handler 内执行同步 `urllib`，会阻塞事件循环。
3. 额外依赖 `mcp` Python 包，安装和版本问题与插件本身无关。
4. MCP tool 描述只能列原子操作，没有 Skill 中的设备恢复、日志游标和副作用重试规则。

### 建议

- `已处理` 现在标记为 `legacy / feature-frozen`，不再把新能力同步到手写 MCP schema。
- 不在本轮直接删除：项目已公开使用，Cursor/Windsurf 等 MCP-only 客户端可能仍有用户。
- 经过一个明确兼容窗口后，在下一次破坏性版本单独删除 `mcp-server/`、requirements 和注册文档。
- HTTP API + Skill CLI 保持稳定，删除 MCP 不影响核心自动化。
- 如果社区确认 MCP 仍有真实需求，不恢复手写模式；应从统一 schema/OpenAPI 自动生成，并使用真正 async client 与 contract tests。

结论：对具备本地 shell/Skill 能力的 AI，Skill + CLI 已足够且更可靠；MCP 只对 MCP-only 客户端有保留价值。

## 8. 构建、发布和测试缺口

### 已验证

- Java 21：`./gradlew test`，当前 21 个测试、0 failure。
- `-Xlint:deprecation` / `-Xlint:unchecked`：生产 Java 无警告。
- `buildPlugin`、`verifyPluginProjectConfiguration`、`verifyPluginStructure`：通过；产物为 `build/distributions/zafrida-ui-0.3.7.zip`。
- Python：Skill CLI、兼容 launcher 与 legacy MCP 通过语法编译；CLI 通过 help、不可达错误和 `retryable=false` 不重试 smoke。
- Skill：使用 `skill-creator` 的 `quick_validate.py` 验证通过。
- 44 个内置 JS 模板通过 `node --check`。
- Frida TS fixture 分别通过本机 16.1.4/12.3.0 与 17.9.1/14.8.2 的 `frida-compile`。

### 仍需补齐

1. `下一阶段` GitHub Actions：macOS/Windows（至少）编译、测试、模板语法、Python CLI、Plugin Verifier。
2. `下一阶段` 配置 `pluginVerification.ides`；当前完整 `verifyPlugin` 没有 IDE matrix。
3. `下一阶段` ToolWindow UI integration test：dispose、项目快速切换、设备刷新乱序、modal dialog callback。
4. `下一阶段` HTTP contract test：Origin、body limit、path traversal、UTF-8 cursor、错误兼容字段。
5. `下一阶段` 真机矩阵：Android USB/Remote/Gadget、双设备、server mismatch、断线重连；iOS USB/remote。
6. `下一阶段` Windows 10 VMware：无 Console fallback、Conda DLL PATH、`.exe/.cmd/.bat`、路径含空格。
7. `下一阶段` Frida 16/17 模板运行 smoke，不只做语法/编译检查。
8. `下一阶段` 发布 changelog/change-notes；Marketplace 当前版本缺少更新说明。
9. `下一阶段` IntelliJ Platform Gradle Plugin/Gradle 9 兼容升级；当前构建仍报告 Gradle plugin 链路的 deprecated feature。

## 9. 推荐实施顺序

1. **Release hardening**：Run/Attach `STARTING` 后台 prepare、operation result、last exit/error、损坏配置备份、Console 上限、API contract tests。
2. **设备可靠性**：显式 ADB device、device probe、server version、ADB future result、forward 决策、真实双设备/断线测试。
3. **UI 迭代**：单一 session toolbar、状态 badge、环境 badge、日志历史/follow、响应式 Templates、持久布局。
4. **AI 扩展**：events/long-poll、operation API、diagnostic bundle、模板/trace log/compatibility endpoints、环境 profile。
5. **TypeScript 产品化**：安全 scaffold、依赖状态、compiler diagnostics、Frida 17 quick-fix。
6. **MCP 删除阶段**：兼容窗口结束后移除 legacy adapter；如必须保留则改为 schema 生成的独立适配器。
