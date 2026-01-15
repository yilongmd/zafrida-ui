中文 | [English](./README.en-US.md)

![ZAFrida UI](doc/logo.svg "ZAFrida UI Logo")
ZAFrida UI - PyCharm Frida Plugin
===============

当前版本： 0.0.7


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


功能特性
-----------------------------------

* **设备与进程管理**: 集成 `frida-ls-devices` 和 `frida-ps`，支持一键刷新设备列表，查看运行进程、正在运行的 App 或已安装的应用。
* **多模式连接**: 完美支持 **USB**、**Remote** (远程主机)、**Gadget** 模式，支持自定义远程 Host 和 Port，无需繁琐的命令行参数。
* **交互式脚本运行**:
  * 支持 **Spawn** (`-f`) 和 **Attach** (`-p`/`-n`) 模式。
  * 支持 **Force Stop** 强制停止目标应用。
  * 内置控制台日志输出，并自动保存日志文件到项目目录 `zafrida-logs/`。
* **动态模板系统 (核心创新)**:
  * 提供 Android/iOS 常用 Hook 模板（如 SSL Pinning Bypass, Method Hook, Native Hook 等）。
  * **复选框控制**: 勾选即生效（插入代码），取消勾选即失效（自动注释代码），无需删除代码。
  * 支持自定义模板，支持从 IDE 编辑器实时预览。
* **项目化配置**:
  * 引入 "ZAFrida Project" 概念，将特定 APP 的 Hook 配置（包名、脚本路径、连接参数）保存为配置文件。
  * 支持在 IDE 中快速创建和切换不同的 Frida 项目。
* **智能环境解析**: 自动识别 PyCharm 当前项目的 Python 环境（venv/conda），确保调用正确的 `frida` 工具链。
* **开发辅助**: 支持一键安装 `frida-gum.d.ts`，为 JS 脚本提供智能代码补全。

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
- 语言: Java 21, Java
- 框架: IntelliJ Platform SDK
- 构建工具: Gradle
- 依赖: `frida``frida-tools` (Python environment)


致谢
-----------------------------------
特别感谢以下大佬为本项目提供的Frida JS 脚本模版支持：

* **小佳**
* **Lane**
* **迷人**