package com.zafrida.ui.fridaproject.ui;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.ComboBox;
import com.intellij.openapi.ui.DialogWrapper;
import com.intellij.ui.components.JBTextField;
import com.zafrida.ui.fridaproject.ZaFridaPlatform;
import com.zafrida.ui.fridaproject.actions.NewZaFridaProjectAction;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import java.awt.*;
/**
 * [UI组件] 新建项目向导对话框。
 * <p>
 * 提供项目名称输入和平台选择 (Android/iOS)。
 * 它是 {@link NewZaFridaProjectAction} 的前端界面。
 */
public final class CreateZaFridaProjectDialog extends DialogWrapper {

    private final JBTextField nameField = new JBTextField();
    private final ComboBox<ZaFridaPlatform> platformCombo = new ComboBox<>(ZaFridaPlatform.values());

    public CreateZaFridaProjectDialog(@Nullable Project project) {
        super(project, true);
        setTitle("Create ZAFrida Project");
        init();
    }

    @Override
    protected @Nullable JComponent createCenterPanel() {
        JPanel p = new JPanel(new GridLayout(2, 2, 8, 8));
        p.add(new JLabel("Name"));
        p.add(nameField);
        p.add(new JLabel("Platform"));
        p.add(platformCombo);
        return p;
    }

    public String getProjectName() { return nameField.getText().trim(); }
    public ZaFridaPlatform getPlatform() { return (ZaFridaPlatform) platformCombo.getSelectedItem(); }
}
