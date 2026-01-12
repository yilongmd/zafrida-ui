package com.github.yilongmd.zafridaui.toolWindow

import com.intellij.openapi.wm.ToolWindow
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPanel
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import com.intellij.util.ui.FormBuilder
import java.awt.BorderLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JPanel

class FridaToolWindow(toolWindow: ToolWindow) {

    private val mainPanel: JPanel
    private val commandInput: JBTextArea
    private val outputArea: JBTextArea
    
    init {
        // Create UI components
        val titleLabel = JBLabel("Frida Tool Window")
        titleLabel.font = titleLabel.font.deriveFont(16f)
        
        commandInput = JBTextArea()
        commandInput.rows = 3
        commandInput.lineWrap = true
        commandInput.wrapStyleWord = true
        
        val executeButton = JButton("Execute Frida Command")
        executeButton.addActionListener {
            executeCommand()
        }
        
        val clearButton = JButton("Clear Output")
        clearButton.addActionListener {
            outputArea.text = ""
        }
        
        outputArea = JBTextArea()
        outputArea.isEditable = false
        outputArea.lineWrap = true
        outputArea.wrapStyleWord = true
        
        val buttonPanel = JPanel()
        buttonPanel.add(executeButton)
        buttonPanel.add(clearButton)
        
        // Build the form
        val formPanel = FormBuilder.createFormBuilder()
            .addComponent(titleLabel)
            .addLabeledComponent("Command:", JBScrollPane(commandInput))
            .addComponent(buttonPanel)
            .addLabeledComponent("Output:", JBScrollPane(outputArea))
            .addComponentFillVertically(JPanel(), 0)
            .panel
        
        mainPanel = JBPanel<JBPanel<*>>(BorderLayout())
        mainPanel.add(formPanel, BorderLayout.CENTER)
        
        // Add welcome message
        outputArea.text = """
            Welcome to Frida Tool Window!
            
            This is a basic Frida UI integration for JetBrains IDEs.
            
            To use this tool:
            1. Enter a Frida command in the text area above
            2. Click 'Execute Frida Command' to run it
            3. View the output below
            
            Note: This is a basic implementation. Full Frida functionality would require
            additional integration with the Frida toolkit.
        """.trimIndent()
    }
    
    fun getContent(): JComponent = mainPanel
    
    private fun executeCommand() {
        val command = commandInput.text
        if (command.isBlank()) {
            outputArea.text = "Error: Please enter a command"
            return
        }
        
        // Basic command execution simulation
        val timestamp = java.time.LocalDateTime.now().toString()
        val output = """
            [$timestamp] Executing Frida command:
            $command
            
            Note: This is a simulated execution. In a full implementation, this would:
            - Connect to a Frida server
            - Execute the command
            - Display real output from Frida
            
            ${outputArea.text}
        """.trimIndent()
        
        outputArea.text = output
    }
}
