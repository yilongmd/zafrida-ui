package com.zafrida.ui.ui;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.DialogWrapper;
import com.intellij.openapi.ui.ValidationInfo;
import com.intellij.ui.components.JBLabel;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.components.JBTextArea;
import com.intellij.ui.components.JBTextField;
import com.intellij.util.ui.JBUI;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import java.awt.*;
/**
 * [UI组件] "添加自定义模板" 对话框。
 * <p>
 * <strong>功能：</strong>
 * 收集用户输入的模板名称和代码内容，并进行基础校验（非空检查）。
 * 它是 {@link ZaFridaTemplatePanel} 中 "Add Template" 动作的前端界面。
 */
public class AddTemplateDialog extends DialogWrapper {

    private final JBTextField nameField;
    private final JBTextArea contentArea;

    public AddTemplateDialog(@NotNull Project project) {
        super(project, true);
        setTitle("Add Custom Template");
        setSize(600, 500);

        nameField = new JBTextField();
        nameField.setColumns(40);

        contentArea = new JBTextArea(20, 60);
        contentArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        contentArea.setText(getDefaultContent());

        init();
    }

    @Override
    protected @Nullable JComponent createCenterPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, JBUI.scale(10)));
        panel.setBorder(JBUI.Borders.empty(10));

        // 名称输入区域
        JPanel namePanel = new JPanel(new BorderLayout(JBUI.scale(8), 0));
        namePanel.add(new JBLabel("Template Name:"), BorderLayout.WEST);
        namePanel.add(nameField, BorderLayout.CENTER);

        // 脚本输入区域
        JPanel contentPanel = new JPanel(new BorderLayout(0, JBUI.scale(4)));
        contentPanel.add(new JBLabel("Script Content:"), BorderLayout.NORTH);
        
        JBScrollPane scrollPane = new JBScrollPane(contentArea);
        scrollPane.setPreferredSize(new Dimension(550, 350));
        contentPanel.add(scrollPane, BorderLayout.CENTER);

        // 提示信息
        JBLabel hintLabel = new JBLabel(
            "<html><small style='color:gray'>Tip: First line comment will be used as title, second line as description</small></html>"
        );

        panel.add(namePanel, BorderLayout.NORTH);
        panel.add(contentPanel, BorderLayout.CENTER);
        panel.add(hintLabel, BorderLayout.SOUTH);

        return panel;
    }

    @Override
    protected @Nullable ValidationInfo doValidate() {
        String name = nameField.getText().trim();
        if (name.isEmpty()) {
            return new ValidationInfo("Template name is required", nameField);
        }
        if (name.length() > 50) {
            return new ValidationInfo("Template name is too long (max 50 characters)", nameField);
        }

        String content = contentArea.getText().trim();
        if (content.isEmpty()) {
            return new ValidationInfo("Script content is required", contentArea);
        }

        return null;
    }

    public @NotNull String getTemplateName() {
        return nameField.getText().trim();
    }

    public @NotNull String getTemplateContent() {
        String content = contentArea.getText();
        String name = getTemplateName();

        // 如果内容不是以注释开头，自动添加标题注释
        if (!content.trim().startsWith("//")) {
            return "// " + name + "\n// Custom Frida script\n\n" + content;
        }
        return content;
    }

    private String getDefaultContent() {
        return """
// Template Title
// Description of what this script does

Java.perform(function() {
    // Your Frida script code here
    console.log("[*] Script loaded");
    
});
""";
    }
}