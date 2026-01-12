# Zafrida-UI Plugin Features

## Overview

This plugin adds a "Frida" tool window to PyCharm and other JetBrains IDEs, providing a UI interface for Frida dynamic instrumentation toolkit.

## Tool Window Location

- **Position**: Right side panel of the IDE
- **Icon**: Custom Frida icon (green square with "F")
- **ID**: "Frida"

## User Interface Components

### 1. Header
- **Title**: "Frida Tool Window" (displayed in larger font)

### 2. Command Input Section
- **Label**: "Command:"
- **Input**: Multi-line text area (3 rows)
  - Supports line wrapping
  - Users can enter Frida commands here

### 3. Control Buttons
- **Execute Frida Command**: Runs the entered command
- **Clear Output**: Clears the output area

### 4. Output Section
- **Label**: "Output:"
- **Display Area**: Multi-line, read-only text area
  - Shows welcome message on startup
  - Displays command execution results
  - Includes timestamp for each command execution
  - Appends new output to existing content

## Usage Flow

1. User opens the Frida tool window from the right panel
2. Welcome message is displayed with instructions
3. User enters a Frida command in the input area
4. User clicks "Execute Frida Command"
5. Output area shows:
   - Timestamp
   - The command that was executed
   - Simulation note explaining this is a basic implementation
   - Previous output (history)

## Implementation Details

### Technologies Used
- **Language**: Kotlin
- **UI Framework**: IntelliJ Platform SDK
  - JBLabel, JBPanel, JBTextArea, JBScrollPane
  - FormBuilder for layout
- **Build System**: Gradle with IntelliJ Gradle Plugin

### Key Classes
1. **FridaToolWindowFactory**: Factory class that creates the tool window
2. **FridaToolWindow**: Main UI component with all visual elements and logic

## Current Limitations

This is a basic implementation that simulates command execution. A full implementation would require:
- Integration with actual Frida toolkit
- Connection to Frida server
- Real command execution
- Process selection UI
- Script management
- Advanced output formatting

## Compatibility

- **Minimum IDE Build**: 232 (IntelliJ Platform 2023.2)
- **Maximum IDE Build**: 242.*
- **Supported IDEs**: All JetBrains IDEs (PyCharm, IntelliJ IDEA, WebStorm, etc.)
