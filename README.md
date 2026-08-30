中文 | [English](./README.en-US.md)

![ZAFrida UI](doc/logo.svg "ZAFrida UI Logo")
ZAFrida UI - PyCharm Frida Plugin
===============

当前版本： 0.3.7


[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![](https://img.shields.io/badge/Author-ZAFrida-orange.svg)](https://github.com/yilongmd/zafrida-ui)
[![](https://img.shields.io/badge/Platform-IntelliJ-brightgreen.svg)](https://plugins.jetbrains.com/)
[![GitHub stars](https://img.shields.io/github/stars/yilongmd/zafrida-ui.svg?style=social&label=Stars)](https://github.com/yilongmd/zafrida-ui)

## 0.3.7 主要更新

- 每个 ZAFrida Project 可独立选择或共享 Python/Frida 环境，默认使用当前 PyCharm 项目解释器，支持 venv、Conda、uv、Poetry、Pipenv、Hatch 等本地环境。
- 重新设计 Session UI 与 Project Settings，完整显示插件、Python 和 Frida 版本信息，并优化自适应、可拖动日志面板与会话状态。
- 完整支持 `.js` / `.ts`、Frida 16/17、多项目环境切换，以及 USB、Remote、Gadget 三种连接流程。
- 强化本地 HTTP API、CLI 与中文 Skill 的设备恢复、会话等待和增量日志能力；移除重复且不稳定的 MCP 适配层。


项目介绍
-----------------------------------

<h3 align="center">专为 PyCharm/IntelliJ 设计的 Frida 图形化工具</h3>

ZAFrida UI 是一款集成在 PyCharm 和 JetBrains 系列 IDE 中的 Frida 图形化操作插件。它旨在解决 Frida 命令行操作繁琐、脚本管理混乱的问题，提供了一套完整的 **UI 交互界面** 来管理设备、进程、脚本和日志。

核心亮点在于其 **"复选框式" 模板管理系统**：用户可以通过勾选/取消勾选，动态地将代码片段插入到主脚本中或将其注释掉，从而实现 "积木式" 的 Hook 脚本组装。同时，插件内置了完整的 **项目化管理** (`zafrida-project.xml`)，支持多设备、多环境配置的快速切换。

ZAFrida 并不替代 Frida，而是作为 `frida-tools` 的强大 UI 外壳，无缝衔接您现有的 Python 和 Frida 环境。

**简易版 Wiki**： [ZAFrida UI 简易 Wiki (BBS)](./zafrida_ui_wiki_bbs_zh.md)（这是更简易的 Wiki）
**详细使用教程**： [ZAFrida UI 详细使用教程 Wiki](./ZAFridaUI_Wiki_zh.md)

## 效果演示
![Home](doc/home.png "Home")

快速入门
-----------------------------------

1.  **安装插件**: 在 IDE 插件市场搜索 "ZAFrida" 或通过磁盘安装。
2.  **配置默认环境**: 默认使用当前 PyCharm 项目的 Python Interpreter；全局 `Settings` -> `Tools` -> `ZAFrida` 仅保留工具名/路径默认值。
3.  **创建项目**: 在项目视图右键 -> `New Frida Project`。
    * 如该项目需要不同的 Frida 版本，打开 ZAFrida `Project Settings`，选择 Python 解释器或环境目录并点击 `Test`。
4.  **编写/选择脚本**: 在 Run 面板选择你的 `agent.js` 或 `agent.ts`。
5.  **Hook 调试**:
* 连接设备 (USB 或 Remote 或 Gadget)。
* 选择目标进程或包名。
* 点击 **Run**。
6.  **使用模板**: 切换到 `Templates` 标签页，勾选你需要的 Hook 功能（如 "SSL Pinning Bypass"），代码会自动注入到你的脚本中。
7.  **Skills 自动化（可选）**: 默认关闭。前往 `Settings/Preferences -> ZAFrida -> Skills HTTP API`，勾选 `Enable Skills` 后可自动启动本地 API（也可手动 `Start/Stop`），CLI 与模板位置：
    * Skill 与主 CLI：`skills-template/zafrida-http-control/`
    * 旧路径兼容启动器：`skills-cli/zafrida_skill_cli.py`

交流群二维码
-----------------------------------
<img src="doc/wx_group_qrcode8.jpeg" alt="ZAFrida与逆向交流群二维码" width="260" />

功能特性
-----------------------------------

* **设备与进程管理**  
  集成 `frida-ls-devices` 与 `frida-ps`，支持一键刷新设备列表，查看运行进程、正在运行的 App 或已安装的应用。

* **多模式连接**  
  完整支持 **USB / Remote / Gadget** 模式，支持自定义远程 Host 与 Port，无需手工拼接复杂命令行参数。

* **交互式脚本运行（Run / Attach）**
  * 支持 **Run（默认 Spawn）** 与 **Attach** 两种执行动作，而非简单的“模式切换”。
  * 支持 **Force Stop** 强制停止目标应用。
  * 内置控制台日志输出，并自动保存日志到项目目录 `zafrida-logs/`。

* **JS / TypeScript 编辑器右键菜单（重要）**
  * 在 Frida `.js` 或 `.ts` 文件编辑区中右键，可直接选择：
    * **Run Frida Script**：以当前文件作为主脚本执行（默认 Spawn）。
    * **Attach Frida Script**：将当前文件作为附加脚本注入到已运行的目标进程。
  * 执行前会自动保存当前文件，并自动切换到脚本所属的 ZAFrida Project。
  * 适合快速 PoC、Demo 验证、Gadget 模式或已运行进程的即时注入。
  * **快捷键**：
    * Windows / Linux：`Ctrl + Alt + S`
    * macOS：`⌘ + ⌥ + S`

* **编辑器右键 Snippets 插入**
  * 在 JS / TypeScript 编辑器右键菜单中提供 **ZAFrida Frida Snippets**。
  * 一键插入常用 Frida 代码片段，例如：
    * `Java.perform` 包裹结构
    * Java 方法 Hook 模板
    * `Interceptor.attach` Native Hook
  * 插入过程遵循 IDE WriteCommandAction，可安全撤销/重做。

* **动态模板系统（核心创新）**
  * 内置 Android / iOS 常用 Hook 模板（如 SSL Pinning Bypass、Method Hook、Native Hook）。
  * **复选框控制**：勾选即插入代码，取消勾选即自动注释代码，无需手动删改。
  * 支持自定义模板，并可在 IDE 内实时预览模板代码。

* **Run Script + Attach Script 分离设计**
  * 支持主 **Run Script** 与独立 **Attach Script** 并存。
  * 适合将“启动期 Hook”与“运行期注入逻辑”解耦，便于复杂调试与长期维护。

* **项目化配置（ZAFrida Project）**
  * 引入 ZAFrida Project 概念，将设备、目标、脚本、Attach Script、连接参数等作为一个完整工作上下文保存。
  * 支持在 Project View 中：
    * `New Frida Project` 创建新项目
    * `Select Frida Project` 快速切换当前激活项目
    * `Load Frida Project` 导入已有项目目录
  * 切换项目后，UI 状态与配置会自动恢复。

* **智能 Python / Frida 环境解析**
  * 默认解析当前 PyCharm 项目的 Python SDK；每个 ZAFrida Project 可单独覆盖解释器或环境目录。
  * 支持本地 system/pyenv、venv/virtualenv、Conda、uv、Poetry、Pipenv、Hatch 环境。
  * 多个 ZAFrida Project 可选择同一路径共享环境，无需复制 venv；适合分别维护 Frida 16/17 环境。
  * 当前 IDE 环境或显式项目环境缺少 `frida-tools` 时直接报错，不会静默串用系统 PATH 中的另一版本；`Test` 可显示实际 Frida 版本。
  * SSH、Docker、Docker Compose、WSL 等远程 Python Interpreter 暂不能用于本机 Frida 子进程。

* **Frida 17 / TypeScript**
  * 文件选择、右键 Run/Attach 和 Snippets 支持 `.js` / `.ts`；Frida 17 的 REPL 会对 `-l agent.ts` 自动编译。
  * 内置模板已迁移到 Frida 17 的现代 Module/NativePointer API，同时保持 Frida 16 常用环境可用。
  * frida-tools REPL 会兼容性携带标准 Java/ObjC bridges；使用 npm/第三方模块 `import` 时应通过 `frida-create -t agent` 或等价工程管理依赖。

* **Skills 本地自动化接口**
  * 本地 Skills HTTP API（默认关闭）支持能力发现、项目/Python 环境、设备与进程、Run/Attach、历史日志列表和基于字节游标的增量日志读取。
  * Skill 内置有界 `wait-device` / `wait-session` 恢复流程，并区分可安全重试的读取与不可自动重放的副作用操作。
  * 开启方式：`Settings/Preferences -> ZAFrida -> Skills HTTP API`，勾选 `Enable Skills`。
  * 配套 CLI 与模板：
    * `skills-template/zafrida-http-control/`（主 Skill 与 CLI）
    * `skills-cli/zafrida_skill_cli.py`（旧路径兼容启动器）

适用场景
-----------------------------------
ZAFrida UI 适用于所有使用 Frida 进行逆向工程的场景，特别是：
* Android / iOS App 渗透测试与逆向分析。
* 需要频繁切换不同 Hook 脚本的调试过程。
* 习惯使用 IDE (PyCharm/IDEA) 进行 Python、JavaScript 和 TypeScript 混合开发的工程师。

技术文档
-----------------------------------

- **环境要求**:
  - IntelliJ IDEA 或 PyCharm (建议 2024.3+)
  - 本地已安装 Python3 及 `frida-tools` (`pip install frida-tools`)
  - 确保 `frida`, `frida-ps`, `frida-ls-devices` 在系统 PATH 中或在插件设置中指定路径。

- **问题反馈**: [Github Issues](https://github.com/yilongmd/zafrida-ui/issues)

启动项目
-----------------------------------

1.  克隆源码: `git clone https://github.com/yilongmd/zafrida-ui.git`
2.  使用 IntelliJ IDEA 打开项目。
3.  运行 Gradle 任务 `runIde` 启动调试环境。

系统效果
-----------------------------------

##### 主界面与运行面板 (Run Panel)
> 提供设备选择、脚本选择、运行模式配置及控制台输出。

![Run Panel](doc/run_panel.png "Run Panel Screenshot")
##### 动态模板管理 (Template Panel)
> 左侧选择分类，中间勾选模板，右侧实时预览代码。勾选框直接控制脚本内容的生效与否。

![Template Panel](doc/template_panel.png "Template Panel Screenshot")
##### 设置界面 (Settings)
> 支持自定义 Frida 工具路径、远程连接地址及日志配置。

![Settings](doc/settings.png "Settings Screenshot")
##### 项目创建向导
> 快速创建标准化的 Frida 项目结构。

![New Project](doc/new_project.png "New Project Dialog")

技术架构
-----------------------------------

#### 开发环境
- 语言: Java 21, Java, 构建脚本使用 Gradle Kotlin DSL
- 框架: IntelliJ Platform SDK
- 构建工具: Gradle
- 依赖: `frida` `frida-tools` (Python environment)


致谢
-----------------------------------
特别感谢以下大佬为本项目提供的Frida JS 脚本模版支持：

* **小佳**
* **Lane**
* **迷人**

更多贡献者与致谢信息请见：[CONTRIBUTORS.md](CONTRIBUTORS.md)
