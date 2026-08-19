

中文 | [English](./README.en-US.md)

![ZAFrida UI](doc/logo.svg "ZAFrida UI Logo")
ZAFrida UI - PyCharm Frida Plugin
===============

当前版本： 0.3.6


[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![](https://img.shields.io/badge/Author-ZAFrida-orange.svg)](https://github.com/yilongmd/zafrida-ui)
[![](https://img.shields.io/badge/Platform-IntelliJ-brightgreen.svg)](https://plugins.jetbrains.com/)
[![GitHub stars](https://img.shields.io/github/stars/yilongmd/zafrida-ui.svg?style=social&label=Stars)](https://github.com/yilongmd/zafrida-ui)


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
2.  **配置环境**: 打开 `Settings` -> `Tools` -> `ZAFrida`，配置 `frida` 可执行文件路径（如果未自动识别）。
3.  **创建项目**: 在项目视图右键 -> `New Frida Project`。
4.  **编写/选择脚本**: 在 Run 面板选择你的 `agent.js`。
5.  **Hook 调试**:
* 连接设备 (USB 或 Remote 或 Gadget)。
* 选择目标进程或包名。
* 点击 **Run**。
6.  **使用模板**: 切换到 `Templates` 标签页，勾选你需要的 Hook 功能（如 "SSL Pinning Bypass"），代码会自动注入到你的脚本中。
7.  **Skills 自动化（可选）**: 默认关闭。前往 `Settings/Preferences -> ZAFrida -> Skills HTTP API`，勾选 `Enable Skills` 后可自动启动本地 API（默认 `http://127.0.0.1:17839/zafrida/api/v1`，也可手动 `Start/Stop`），CLI 与模板位置：
    * `skills-cli/zafrida_skill_cli.py`
    * `skills-template/zafrida-http-control/`

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

* **JS 编辑器右键菜单（重要）**
  * 在 Frida JS 文件编辑区中右键，可直接选择：
    * **Run Frida JS**：以当前 JS 文件作为主脚本执行（默认 Spawn）。
    * **Attach Frida JS**：将当前 JS 文件作为附加脚本注入到已运行的目标进程。
  * 执行前会自动保存当前文件，并自动切换到脚本所属的 ZAFrida Project。
  * 适合快速 PoC、Demo 验证、Gadget 模式或已运行进程的即时注入。
  * **快捷键**：
    * Windows / Linux：`Ctrl + Alt + S`
    * macOS：`⌘ + ⌥ + S`

* **编辑器右键 Snippets 插入**
  * 在 JS 编辑器右键菜单中提供 **ZAFrida Frida Snippets**。
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
  * 自动解析当前 PyCharm 项目的 Python SDK（venv / conda）。
  * 动态注入 PATH，确保调用正确的 `frida` / `frida-tools`。
  * 对 Remote / Gadget 场景进行兼容处理，避免误注入本地环境。

* **开发辅助功能**
  * 支持一键安装 `frida-gum.d.ts`，为 Frida JS 提供类型提示与智能补全。

* **Skills 本地自动化接口**
  * 新增本地 Skills HTTP API（默认关闭），可用于脚本化控制项目切换、设备/连接模式设置、Run/Attach 触发、日志路径与日志内容读取。
  * 开启方式：`Settings/Preferences -> ZAFrida -> Skills HTTP API`，勾选 `Enable Skills`。
  * 配套 CLI 与模板：
    * `skills-cli/zafrida_skill_cli.py`
    * `skills-template/zafrida-http-control/`

适用场景
-----------------------------------
ZAFrida UI 适用于所有使用 Frida 进行逆向工程的场景，特别是：
* Android / iOS App 渗透测试与逆向分析。
* 需要频繁切换不同 Hook 脚本的调试过程。
* 习惯使用 IDE (PyCharm/IDEA) 进行 Python 和 JS 混合开发的工程师。

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
