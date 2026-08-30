## Frida UI Tool (ZAFrida) Detailed Guide

### Q1: Why build it as a PyCharm/IntelliJ plugin?

To fully use IDE editing capabilities, Git integration, and project management.

---
### Q2: What are the advantages of editing JS scripts in an IDE?

- Syntax highlighting, completion, folding, and other editing features
- AI-assisted coding (e.g., CodeWhisperer, Copilot)
- Version control (git, etc.) and team collaboration
- Multi-file management
- Multi-project management

---

### Q3: Why save logs for every debug session?

- Console output is temporary on any OS; it disappears when the IDE closes
- Console has capacity limits; long output gets truncated
- Log files are easier to analyze later and share

---

### Q4: Will the template library keep growing?

- I have already discussed with several experts; their real-world templates and mine will be added to the template library over time. PRs are welcome for sharing your own templates.

---

### 0x00 Summary first: what is ZAFrida UI?

**ZAFrida UI is a Frida GUI plugin integrated into PyCharm/IntelliJ. You can right-click a JavaScript or TypeScript file to Run/Attach it, and ZAFrida automatically switches to the matching project context (device/package/connection/args). It also provides editor Snippets and a checkbox-based template system for assembling Hook scripts.**

[Open Source Repo](https://github.com/yilongmd/zafrida-ui)

![](doc/home.png "home")

---

### 0x01 Prepare environment (shortest path)

- If your CLI frida workflow already works, you are good. Recommend installing a specific version matched to your device to avoid weird mismatches.
1. Install `frida-tools` in local Python
2. Verify in terminal: `frida --version`, `frida-ls-devices`
3. Ensure device-side frida-server / gadget ready

---

### 0x02 Install plugin

IDE -> Plugins -> Marketplace -> search **ZAFrida** -> Install -> Restart

![](doc/qs_install_plugin.png "qs_install_plugin")

---

### 0x03 First open: Environment Doctor

First open ZAFrida ToolWindow usually auto pops Doctor.

Doctor default checks:

- Python Environment (active ZAFrida Project override first, otherwise the IDE interpreter)
- Frida Tools Path
- frida --version
- frida-ls-devices
- Selected Device Connectivity (if device selected)
- adb availability (Android)

> adb is optional, but if you do Android reversing, install it so you can Force Stop / Open App from Run panel.

![](doc/qs_doctor_first_run.png "qs_doctor_first_run")
> If it did not pop, you can open manually:
>
![](doc/qs_docktor_click.png "qs_docktor_click")

---

### 0x04 Create your first ZAFrida project

Project View right click:

- **New Frida Project**

Choose Android / iOS and enter project name.

> Both entry points are fast:

![](doc/qs_new_project_dialog.png "qs_new_project_dialog")
![](doc/new_project.png "new_project")

---

### 0x05 Run panel: fill 4 fields and go

In ZAFrida -> Run panel:
> It defaults to the newly created project
1. Project: select project
2. Device: select device
3. Run Script: select script
4. Target: package name / process name

Then click:

- Run (Spawn) or Attach (inject into running process)
> If you need Gadget mode, click the Frida project settings (Project button) on the top right:

![](doc/settings2.png "settings2")

### 0x06 Key highlight: editor right-click Run/Attach

Open any `.js` / `.ts` file -> right click:

- Run Frida Script
- Attach Frida Script

> It auto switches to the project based on script path and executes.

> This makes it easy to handle multi-app, multi-device, and multi-connection-mode debugging.

![](doc/editor_menu_run_attach.png "editor_menu_run_attach")

---

### 0x07 Snippets: insert common Hook snippets

Right click -> ZAFrida Frida Snippets:

- Java.perform
- hook Java method
- Interceptor.attach
- backtrace (ACCURATE/FUZZY)
- enumerate modules, etc.

![](doc/snippets_menu.png "snippets_menu")

---

### 0x08 Templates: checkbox templates (check = insert, uncheck = comment)

ZAFrida -> Templates:

- Check template: insert or uncomment
- Uncheck template: line-comment with `//`, do not delete

Template block marker example:

```js
// ===== [ZaFrida Template Start: <id>] =====
...
// ===== [ZaFrida Template End: <id>] =====
```

![](doc/template_panel.png "template_panel")

---

### 0x09 Logs and Console

- Console: Run/Attach tabs
- Log files: default `zafrida-logs/`
- Run panel bottom `Log:` shows path

![](doc/qs_logs_ok.png "qs_logs_ok")

---

### 0x0A Common notifications (do not panic on bubbles)

Common tips:

- No device selected -> select device
- Target is empty -> fill package name
- No script file selected -> select script
- No Frida project found for this script -> script not under project directory
- Environment Doctor Found N issues -> open Doctor for details

![](doc/notify_example.png "notify_example")

---

(End)

---
