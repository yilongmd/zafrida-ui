# Development Guide

## Project Structure

This is a JetBrains IDE plugin that provides a Frida UI tool window.

```
zafrida-ui/
├── src/main/
│   ├── kotlin/com/github/yilongmd/zafridaui/
│   │   └── toolWindow/
│   │       ├── FridaToolWindowFactory.kt  # Factory for creating the tool window
│   │       └── FridaToolWindow.kt         # Main UI component
│   └── resources/
│       ├── META-INF/
│       │   └── plugin.xml                 # Plugin configuration
│       └── icons/
│           └── frida.svg                  # Tool window icon
├── build.gradle.kts                       # Build configuration
├── gradle.properties                      # Plugin metadata
└── settings.gradle.kts                    # Gradle settings

```

## Building the Plugin

To build the plugin, run:

```bash
./gradlew buildPlugin
```

The plugin will be created in `build/distributions/`.

## Running the Plugin in Development

To test the plugin in a sandboxed IDE instance:

```bash
./gradlew runIde
```

## Features

The plugin provides a tool window that includes:

1. **Command Input**: A text area for entering Frida commands
2. **Execute Button**: Executes the entered command
3. **Clear Button**: Clears the output area
4. **Output Area**: Displays command execution results and messages

## Architecture

### FridaToolWindowFactory

This class implements `ToolWindowFactory` and is responsible for:
- Creating the tool window content when the IDE requests it
- Initializing the FridaToolWindow instance
- Registering the content with the tool window manager

### FridaToolWindow

This class contains the UI logic and includes:
- Command input text area
- Output display area
- Action buttons for executing commands and clearing output
- Welcome message with usage instructions

## Configuration

Key plugin properties are defined in `gradle.properties`:
- `pluginVersion`: Current plugin version
- `pluginSinceBuild`: Minimum IDE build number
- `pluginUntilBuild`: Maximum IDE build number
- `platformVersion`: Target IntelliJ Platform version

## Future Enhancements

This is a basic implementation. Future versions could include:
- Actual Frida integration
- Process selection UI
- Script management
- Output syntax highlighting
- Persistent settings
