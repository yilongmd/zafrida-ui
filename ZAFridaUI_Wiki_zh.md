# ZAFrida UI 详细使用教程 Wiki
## 目录

- [首页](#home)
- [00 QuickStart](#sec-00-quickstart)
- [01 准备环境](#sec-01-prepare)
- [02 安装插件](#sec-02-install)
- [03 医生模块](#sec-03-doctor)
- [04 项目管理](#sec-04-projects)
- [05 Run 面板](#sec-05-run-panel)
- [06 编辑区右键 Run/Attach](#sec-06-editor-run-attach)
- [07 Snippets](#sec-07-snippets)
- [08 Templates](#sec-08-templates)
- [09 日志与控制台](#sec-09-logs-console)
- [10 通知与提醒](#sec-10-notifications)
- [11 Troubleshooting](#sec-11-troubleshooting)
- [12 FAQ](#sec-12-faq)
- [13 快捷键与小技巧](#sec-13-shortcuts-tips)
---

<a id="home"></a>

## ZAFrida UI 使用教程 Wiki（v0.2.7）

> 适用读者：日常用 Frida 做 Android/iOS 逆向 / Hook 调试 / PoC 验证的人；希望把脚本、设备、目标、日志用“项目化方式”管理的人。

---

<a id="sec-00-quickstart"></a>

## 00 QuickStart（3 分钟跑通）

目标：**第一次在 IDE 里跑通 Run / Attach**，确认你的环境没问题。

---

### 0x00 你需要准备

- JetBrains IDE：PyCharm（推荐）或 IntelliJ（需要 Python 插件）
- 本地 Python 3（建议 venv/conda）
- 已安装 `frida-tools`
- 设备侧按你自己的工作流准备：
  - Android：frida-server / frida-gadget
  - iOS：frida-server / gadget（或你自己的注入方案）
---

### 0x01 安装插件

- IDE → Plugins → Marketplace → 搜索 **ZAFrida** → Install  
- 重启 IDE（如果提示）

>![](doc/qs_install_plugin.png "qs_install_plugin")

---

### 0x02 打开 ZAFrida 工具窗口

- IDE 右侧 ToolWindow → 打开 **ZAFrida**

首次打开通常会自动弹出 **Environment Doctor**（环境医生）：

![](doc/qs_docktor_click.png "qs_docktor_click")
![](doc/qs_doctor_first_run.png "qs_doctor_first_run")

---

### 0x03 创建第一个 ZAFrida Project

两种入口任选一种：

- Project View 右键 → **New Frida Project**
- ZAFrida 工具窗口顶部 → **New Project**

选择平台（Android/iOS）+ 填项目名 → Create

![](doc/qs_new_project_dialog.png "qs_new_project_dialog")

---

### 0x04 在 Run 面板选好 4 个字段，然后 Run

在 **Run** 面板里：

1. **Project**：选择你刚创建的项目  
2. **Device**：刷新并选择设备  
3. **Run Script**：选择该项目目录下默认生成的 `xxx.js`，也可选择自己的 `agent.js` / `agent.ts`
4. **Target**：填包名/进程名（通常是包名）

然后点：

- **Run**（Spawn）或  
- **Attach**（注入已运行进程）

![](doc/qs_run_panel_filled.png "qs_run_panel_filled")
---

### 0x05 验证：看到日志 + 有落盘 log

- 底部 Console 出现输出
- 工程目录出现 `zafrida-logs/`（默认）并生成日志文件
- Run 面板底部 `Log:` 显示本次 log 文件路径

![](doc/qs_logs_ok.png "qs_logs_ok")

---

下一步建议看：
- [03-Doctor](03-Doctor)（环境不稳先跑 Doctor）
- [06-Editor-Run-Attach](06-Editor-Run-Attach)（核心爽点：编辑区右键 Run/Attach，方便我们应对多个 App、多台设备、多种连接模式的调试场景）

---

<a id="sec-01-prepare"></a>

## 01 准备环境（IDE / Python / Frida / 设备）

这页只做两件事：**让 Doctor 全绿**，以及确保你能从命令行跑通 frida-tools。

---

### 0x00 IDE 选择与要求

- 推荐：**PyCharm 2024.3+**
- IntelliJ IDEA 也可，但需要安装/启用 **Python 插件**（否则 Doctor 可能无法解析 Python SDK）
---

### 0x01 Python 环境

默认使用当前 PyCharm 项目的 Python Interpreter。每个 ZAFrida Project 也可在 `Project Settings -> Python Environment` 单独选择解释器文件或环境根目录，并用 `Test` 确认实际 Frida 版本。

支持本地 system/pyenv、venv/virtualenv、Conda、uv、Poetry、Pipenv、Hatch。多个 ZAFrida Project 可以选择同一路径共享环境，不会复制 venv。SSH、Docker、Docker Compose、WSL 等远程解释器暂不支持本机 Frida 子进程。
```bash
python -m pip install frida frida-tools
```

长期项目建议在各自环境中用 `==` 固定已经验证过的 `frida` / `frida-tools` 组合。

验证：

```bash
frida --version
frida-ls-devices
```

Frida 17 的 frida-tools REPL 可直接加载 `.ts`；Frida 16 环境请先用 `frida-compile` 生成 `.js`。ZAFrida 不会在两个环境之间静默回退。

---

### 0x02 设备侧准备

Android/iOS中确保你平时使用命令行的时候可以正常连接就行

---

### 0x03 如果你只做一步：先把 Doctor 跑通

打开 ZAFrida → 点顶部 **Doctor** → 全部检查项 success

- [03-Doctor](03-Doctor)

---

<a id="sec-02-install"></a>

## 02 安装插件（ZAFrida UI）

---

### 0x00 从 Marketplace 安装（推荐）

1. IDE → **Plugins**
2. Marketplace 搜索：`ZAFrida`
3. Install → 重启 IDE

![](doc/qs_install_plugin.png "qs_install_plugin")

---

### 0x01 从磁盘安装（离线/自编译）

1. github上的Release中下载插件包（zip）
2. IDE → Plugins → ⚙️ → Install Plugin from Disk...
3. 选择 zip → 重启
---

### 0x02 打开设置入口

- IDE Settings/Preferences → **Tools** → **ZAFrida**

- 前面步骤正确, 这里不用去设置了也行, 除非你想修改一些全局配置

---

<a id="sec-03-doctor"></a>

## 03 医生模块（Environment Doctor）

Environment Doctor 用来把“环境问题”变成**可定位的检查项**。强烈建议首次使用先跑一遍。

---

### 0x00 它什么时候会出现？

- **第一次打开 ZAFrida ToolWindow** 时，会自动弹一次  
- 之后你可以随时手动打开：顶部按钮 **Doctor**

![](doc/qs_doctor_first_run.png "qs_doctor_first_run")

---

---

### 0x01 常见失败怎么修

#### A. Python Environment 失败

- 未配置项目覆盖时：IDE → Settings → Python Interpreter，选择有效的本地解释器。
- 已配置项目覆盖时：ZAFrida `Project Settings` 检查路径并点击 `Test`。
- 当前 IDE 环境和显式项目环境都不会回退到系统 PATH 中的另一套 Frida；请在实际选择的环境中安装匹配版本的 `frida-tools`。

#### B. Frida Tools Path / frida --version 失败

- 确认当前项目选中的 Python 环境里已安装：`pip show frida-tools`
- 或在 ZAFrida Settings 手动指定 `frida / frida-ps / frida-ls-devices` 路径

#### C. frida-ls-devices 失败

- 设备端 frida-server 未启动 / 端口不通 / 版本不匹配

#### D. adb availability 失败

- 装 Android SDK platform-tools，并把 `adb` 加入 PATH
- 这个失败没关系, 不强制

---

<a id="sec-04-projects"></a>

## 04 ZAFrida 项目管理（New / Load / Select）

ZAFrida 的“项目”是你日常逆向最核心的上下文：脚本、目标、连接方式、设备、extra args 都跟着走。

---

### 0x00 三个入口（都在 Project View 右键菜单）

在 Project View 对任意目录右键：

- **New Frida Project**：创建新项目（推荐新手）
- **Load Frida Project**：把已有的项目目录载入到工作区
- **Select Frida Project**：把某个已载入项目切为当前激活项目

> 建立在JS中直接使用Run Frida JS, 这样切换项目比Select Frida Project方便得多(这个是早期开发预留的)。这也更方便我们应对多个 App、多台设备、多种连接模式的调试场景。

---

### 0x01 什么时候用 Load？

典型场景：

- 你从同事那里拿到一整个 `android/app_xxx/` 目录
- 或你在别处存了一份 `zafrida-project.xml` 项目目录

要求：该目录里必须存在 `zafrida-project.xml`。


---

### 0x02 什么时候用 Select？

当你同时维护多个目标 App：

- 先 Load（或 New）多个项目
- 再 Select 切换当前项目  
  （Run 面板的 Project 下拉也可以切）
---

<a id="sec-05-run-panel"></a>

## 05 Run 面板（Device / Script / Target / Run / Attach）

Run 面板负责把 frida-tools 的常用参数变成“可视化字段”。

![](doc/qs_run_panel.png)

---

### 0x00 Run 面板字段说明（对着 UI 操作即可）

#### 1) Project

- 选择当前激活的 ZAFrida 项目
- 旁边会显示平台图标（Android/iOS）与插件版本
- 如果出现 **Update available(有更新)**，点它会跳到 Plugins 更新页

#### 2) Device

- 选择设备（USB / Remote / Gadget）
- 按 **刷新** 按钮重新枚举
- 点 **+** 可快速添加一个远程 `host:port`（会写入全局 Remote Hosts）

#### 3) Run Script

- 选择 Run（Spawn）时要注入的脚本
- 右侧两个按钮：
  - 📍 Locate：在 Project View 定位脚本
  - 📂 Choose：选择脚本文件

#### 4) Attach Script

- 选择 Attach（注入已运行进程）时用的脚本
- 典型用法：把“启动期 Hook”与“运行期注入”拆分成两份脚本

#### 5) Target

- 填包名/进程名（Spawn/Attach 都依赖它）
- 新手建议：直接填包名（Android `com.xxx`，iOS bundle id）

#### 6) Extra (Args)

- 额外传给 frida 的参数（如 `--realm=emulated` 等）
- 会持久化到当前项目配置里

---

### 0x01 按钮说明（Run/Attach/Stop + 两个 App 按钮）

按钮（从左到右）：

- **Run**：Spawn 启动并注入
- **Attach**：注入到已运行进程
- **Stop**：停止当前会话
- **S App（红色取消图标）**：Force Stop（Android，需要 adb + 包名）
- **S App（运行图标）**：Open App（Android，需要 adb + 包名）
- **Clear Console**：清空当前激活的控制台 tab
> ![](doc/run_buttons_row.png)

---

### 0x02 运行后你应该看到什么？

- Console 有输出（Run/Attach 分 tab）
- 工程内生成 `zafrida-logs/` 并落盘 `.log`
- Run 面板底部 `Log:` 显示本次 log 路径
---

<a id="sec-06-editor-run-attach"></a>

## 06 编辑区右键 Run/Attach（核心爽点）

你不再从“命令行参数”出发，而是从“脚本文件”出发。这也是我们应对多个 App、多台设备、多种连接模式调试的核心方式。

---

### 0x00 两个菜单

在任意 `.js` / `.ts` 编辑器里右键：

- **Run Frida Script**
- **Attach Frida Script**

执行前会自动保存文件。

![](doc/editor_menu_run_attach.png)

---

### 0x01 为什么它能自动切项目？

它会从当前脚本所在目录向上回溯，寻找最近的：

- `zafrida-project.xml`

找到即认为该脚本属于该 ZAFrida 项目，然后：

- 自动激活该项目（Project 下拉切换）
- 自动把当前脚本设置为 Run Script / Attach Script
- 立即执行 Run / Attach

---

### 0x02 什么时候会失败（以及你会看到什么提醒）

#### A. 脚本不在任何 ZAFrida 项目里

通知气泡：`No Frida project found for this script`

修复：把脚本放到包含 `zafrida-project.xml` 的项目目录下（或先 Load 项目）。

#### B. 项目目录不在 IDE 工程根目录下

通知气泡：`Frida project is not under IDE root`

修复：把项目目录移动到当前打开的 IDE 工程根目录范围内。

---

### 0x03 快捷键（默认）

- Windows / Linux：`Ctrl + Alt + S`
- macOS：`⌘ + ⌥ + S`

---

<a id="sec-07-snippets"></a>

## 07 Snippets：右键插入常用 Frida JS 片段

目标：把“样板代码”从你的脑子里搬到右键菜单里。

---

### 0x00 在哪里？

在 `.js` / `.ts` 编辑器里右键：

- **ZAFrida Frida Snippets**（子菜单）

![](doc/snippets_menu.png)

---

### 0x01 内置片段（当前版本）

- `Frida: Java.perform block`
- `Frida: hook Java method`
- `Frida: print Java stack trace`
- `Frida: Interceptor.attach`
- `Frida: backtrace (ACCURATE)`
- `Frida: backtrace (FUZZY)`
- `Frida: Thread.currentContext`
- `Frida: enumerate modules`
- `Frida: send log message`


---

### 0x02 你会“感觉更舒服”的点

- 支持撤销/重做（Ctrl+Z）
- 不依赖剪贴板，格式不会漂

---

<a id="sec-08-templates"></a>

## 08 Templates：复选框式模板管理（核心能力）

模板面板让 Hook 代码像积木一样组合：**勾选=插入/取消注释，取消勾选=按行注释（不删除）**。
![](doc/template_panel.png)

---

### 0x00 面板布局（从左到右）

- 分类：Favorites / Android / iOS / Custom
- 模板列表：复选框 + 搜索过滤
- 预览区：标题/描述 + 代码预览 + Copy/Open Folder

---

### 0x01 勾选/取消勾选会发生什么？

脚本文件里会出现带 marker 的模板块：

```js
// ===== [ZaFrida Template Start: <templateId>] =====
... template content ...
// ===== [ZaFrida Template End: <templateId>] =====
```

- 勾选：
  - 不存在 → 插入模板块到脚本末尾
  - 已存在且被注释 → 自动取消注释
- 取消勾选：
  - 不删除模板块
  - 给模板块内每一行加 `// ` 前缀（按行注释）


---

### 0x02 选择脚本文件（重要）

Templates 面板需要知道“你正在编辑哪一个脚本”：

- 当你在 Run 面板选择 Run Script 时，会自动绑定到该脚本
- 如果你没选脚本，勾选模板会提示：`No script file selected`


---

### 0x03 Custom 模板（建议你放自己改过的模板）

全局设置里可以选择模板根目录：

- System (User Home)：`~/.zafrida/templates/`
- IDE Project Root：`<project>/.zafrida/templates/`

目录结构：

```text
templates/
  android/   (内置，可能被覆盖更新)
  ios/       (内置，可能被覆盖更新)
  custom/    (你的自定义模板，推荐放这里)
```

---

### 0x04 常用操作按钮

- 刷新：重新加载模板
- Add custom template：新增自定义模板
- Delete custom template：删除自定义模板
- Toggle favorite：收藏/取消收藏
- Copy Selected：把勾选的模板一次性复制到剪贴板

---

<a id="sec-09-logs-console"></a>

## 09 日志与控制台（Console + 落盘日志）

---

### 0x00 Console 有两个（Run / Attach 分离）

- Run 的输出在 Run Console
- Attach 的输出在 Attach Console

![](doc/console_tabs.png)

---

### 0x01 落盘日志在哪里？

默认目录（可在 Settings 修改）：

- `zafrida-logs/`

Run 面板底部会显示：

- `Log: <path>`


---

### 0x02 清空控制台

- 点击 **Clear Console**（会清空当前激活的 console tab）
- 右键也可以清空, 与平时清空IDE自带的 console 一样

---

<a id="sec-10-notifications"></a>

## 10 通知与提醒（哪些情况会弹气泡？）

ZAFrida 会通过 IDE 的 Balloon Notification 提示你“当前操作为什么失败”。

![](doc/notify_example.png)

---

### 0x00 常见通知与含义（按出现频率）

#### 1) Project name is empty

- 创建项目时项目名为空  
修复：填一个名字再创建。

#### 2) Invalid script file / Script file not found

- 你选的脚本路径无效/文件不存在  
修复：重新选择脚本；确认在工程目录内。

#### 3) No script file selected / No attach script file selected

- 点击 Run/Attach 时没有选择对应脚本  
修复：在 Run 面板选 Run Script / Attach Script。

#### 4) Target is empty

- 没填包名/进程名  
修复：填 Target（新手用包名最稳）。

#### 5) No device selected

- 未选择设备  
修复：Device 下拉选择设备，必要时刷新。

#### 6) Start failed: ...

- frida 启动失败（参数、连接、版本不匹配等）  
修复：先跑 [03-Doctor](03-Doctor)，再看 Console 的详细错误。

#### 7) Force stop requires a package name / Open app requires a package name

- 你点了 Force Stop / Open App，但 Target 为空  
修复：填包名（Android）。

#### 8) No Frida project found for this script

- 编辑器右键 Run/Attach 时，找不到脚本所属项目  
修复：把脚本放到包含 `zafrida-project.xml` 的目录下（或 Load 项目）。多个 App、多台设备、多种连接模式切换时尤其要确认脚本归属项目。

#### 9) ZAFrida tool window not available / run panel not initialized

- ToolWindow 还没打开或 IDE 状态异常  
修复：先打开 ZAFrida ToolWindow，再重试。

#### 10) Environment Doctor: Found N issues

- Doctor 跑完发现问题  
修复：打开 Doctor 看具体失败项与 tip。

---

### 0x01 建议：遇到通知先看哪里？

优先级顺序：

1. **Console 输出**（更完整）
2. **Doctor**（更结构化）
3. **Settings**（路径/remote hosts 等）

---

<a id="sec-11-troubleshooting"></a>

## 11 Troubleshooting（按症状排查）

这页按“你看到的现象”给最短路径。

---

### 0x00 症状：Device 列表空 / 刷新无反应

1. 先跑 Doctor：`frida-ls-devices` 是否成功？
2. 命令行跑一遍：`frida-ls-devices`
3. Remote：确认 `host:port` 可达（默认 14725）


---

### 0x01 症状：Run 直接失败（Start failed）

1. 看 Console 最后一段错误  
2. Doctor 检查 `frida --version` / `frida-ls-devices` / `frida-ps`
3. 常见原因：
   - frida-server 未启动
   - 版本不匹配
   - Target 写错（包名/进程名）
   - Remote host/port 不通


---

### 0x02 症状：Attach 找不到进程 / 注入无输出

1. 先确认目标进程确实在运行  
2. 用 Project Settings → Select from device 刷新 targets（可选）  
3. 尝试换 scope（RUNNING_APPS / RUNNING_PROCESSES 等）

---

### 0x03 症状：模板勾选没效果

1. 你有没有选 Run Script（Templates 需要知道当前脚本）  
2. 看脚本里有没有 marker：
   - `// ===== [ZaFrida Template Start: ...] =====`


---

### 0x04 症状：Force Stop / Open App 不工作

- 功能非强制, 只是提供方便
- 这两个依赖 adb，仅对 Android 有意义  
- Doctor 的 `adb availability` 必须成功  
- Target 必须是包名

---

### 0x05 症状：编辑器右键 Run/Attach 找不到项目

- 脚本必须位于包含 `zafrida-project.xml` 的目录树内  
- 且该目录必须在当前打开的 IDE 工程根目录下
- 多个 App、多台设备、多种连接模式调试时，优先检查脚本是否在正确项目内


---

<a id="sec-12-faq"></a>

## 12 FAQ

---

### Q1：ZAFrida UI 会替代 frida-tools 吗？

不会。它依赖你本地的 `frida / frida-tools`，只是把常用工作流工程化到 IDE 里。

---

### Q2：我一定要用 PyCharm 吗？

推荐 PyCharm。IntelliJ IDEA 也能用，但要确保 Python 插件可用，否则 Doctor 可能无法解析 Python SDK。

---

### Q3：默认生成的入口脚本为什么是 `<projectName>.js`？

新建项目会用项目名生成入口脚本文件名。你可以在 Run Script 里重新选择你喜欢的 `agent.js`。

---

### Q4：Templates 取消勾选为什么不删除？

为了可追溯、可回滚、可组合。取消勾选会把模板块按行注释（不会丢代码）。

---

### Q5：为什么我在模板目录改了内置模板，重启又变了？

当前版本内置模板可能会被插件刷新覆盖。建议把修改后的模板放到 `custom/` 目录。

---

### Q6：如何把一个项目给同事？

建议直接使用git管理项目(非常舒服)，或者直接:
把整个 `android/<proj>/` 或 `ios/<proj>/` 目录（含 `zafrida-project.xml`）打包给同事即可。同事在自己 IDE 工程里用 **Load Frida Project** 导入。

---

<a id="sec-13-shortcuts-tips"></a>

## 13 快捷键与小技巧

---

### 0x00 默认快捷键

- Run Frida JS：Windows/Linux `Ctrl + Alt + S`，macOS `⌘ + ⌥ + S`
- Attach Frida JS：同样在右键菜单里（可自定义快捷键）

---

### 0x01 小技巧：把脚本当入口，不要当参数

- 脚本放进正确的 ZAFrida 项目目录
- 编辑器里右键 Run/Attach，方便我们应对多个 App、多台设备、多种连接模式的调试场景
- 减少“跑错设备/跑错包/跑错参数”

---

### 0x02 小技巧：Run Script / Attach Script 分离

- 启动期 Hook：放 Run Script
- 运行中临时注入：放 Attach Script
- 复杂场景更不容易乱

---

<a id="sec-forum-tutorial"></a>

## ZAFrida UI 详细使用教程（论坛单篇版）

> 适用读者：日常用 Frida 做 Android/iOS 逆向 / Hook 调试的人。  
> 目标：让新手在 10 分钟内上手：**创建项目 → 选择设备/脚本/目标 → Run/Attach → 模板勾选组合**。  


---

### 0x00 先看结论：ZAFrida UI 是干嘛的？

**ZAFrida UI 是一个集成到 PyCharm/IntelliJ 的 Frida 图形化插件：你在 JavaScript/TypeScript 编辑区右键就能 Run/Attach 当前脚本，并且会根据脚本路径自动切换到对应的 ZAFrida 项目上下文（设备/包名/连接方式/参数）；同时提供右键 Snippets 和复选框模板系统，把 Hook 脚本当积木组装。**
这也非常方便我们应对多个 App、多台设备、多种连接模式的调试场景。

![](doc/home.png "home")

---

### 0x01 准备环境（最短路径）

- 确认你平时可以正常使用frida就行, 建议安装指定的版本(与手机对应), 以免版本不匹配导致各种奇怪的问题
1. 本地 Python 里安装 `frida-tools`  
2. 终端确认能跑：`frida --version`、`frida-ls-devices`  
3. 设备侧确保 frida-server / gadget 已就绪

---

### 0x02 安装插件

IDE → Plugins → Marketplace → 搜索 **ZAFrida** → Install → 重启

![](doc/qs_install_plugin.png "qs_install_plugin")

---

### 0x03 第一次打开：医生模块（Environment Doctor）

首次打开 ZAFrida ToolWindow 通常会自动弹出 Doctor。

Doctor 默认检查：

- Python Environment（活动 ZAFrida 项目覆盖优先，否则使用 IDE Interpreter）
- Frida Tools Path
- frida --version
- frida-ls-devices
- Selected Device Connectivity（若已选设备）
- adb availability（Android）

>adb非强制, 不过如果你做 Android 逆向建议装一下, 这样可以直接在 Run 面板 Force Stop / Open App

![](doc/qs_doctor_first_run.png "qs_doctor_first_run")
>如果没有弹出, 可以手动打开:
> 
![](doc/qs_docktor_click.png "qs_docktor_click")

---

### 0x04 创建你的第一个 ZAFrida 项目

Project View 右键：

- **New Frida Project**

选择 Android / iOS，输入项目名。

>两个方式都可以快速创建:

![](doc/qs_new_project_dialog.png "qs_new_project_dialog")
![](doc/new_project.png "new_project")

---

### 0x05 Run 面板：选 4 个字段就能跑

在 ZAFrida → Run 面板：
>默认会选择刚创建的项目
1. Project：选项目  
2. Device：选设备  
3. Run Script：选脚本  
4. Target：填包名/进程名

然后点：

- Run（Spawn）或 Attach（注入已运行进程）
>如果需要Gadget等模式, 点击右上角Frida项目设置(Project按钮)配置:

![](doc/settings2.png "settings2")

### 0x06 核心爽点：编辑器右键 Run/Attach

打开任意 `.js` / `.ts` 文件 → 右键：

- Run Frida Script
- Attach Frida Script

它会根据脚本路径自动切换到所属项目并执行。这对多个 App、多台设备、多种连接模式的调试场景尤其方便。

![](doc/editor_menu_run_attach.png "editor_menu_run_attach")

---

### 0x07 Snippets：右键插入常用 Hook 片段

右键 → ZAFrida Frida Snippets：

- Java.perform
- hook Java method
- Interceptor.attach
- backtrace (ACCURATE/FUZZY)
- enumerate modules 等

![](doc/snippets_menu.png "snippets_menu")

---

### 0x08 Templates：复选框式模板（勾选=插入，取消=注释）

ZAFrida → Templates：

- 勾选模板：插入或取消注释
- 取消勾选：按行 `//` 注释，不删除

模板块 marker 示例：

```js
// ===== [ZaFrida Template Start: <id>] =====
...
// ===== [ZaFrida Template End: <id>] =====
```

![](doc/template_panel.png "template_panel")

---

### 0x09 日志与控制台

- Console：Run/Attach 分 tab
- 落盘日志：默认 `zafrida-logs/`
- Run 面板底部 `Log:` 显示路径

![](doc/qs_logs_ok.png "qs_logs_ok")

---

### 0x0A 常见通知（看到气泡别慌）

常见提示：

- No device selected → 选设备
- Target is empty → 填包名
- No script file selected → 选脚本
- No Frida project found for this script → 脚本不在项目目录下
- Environment Doctor Found N issues → 打开 Doctor 看失败项

![](doc/notify_example.png "notify_example")

---

（完）

---
