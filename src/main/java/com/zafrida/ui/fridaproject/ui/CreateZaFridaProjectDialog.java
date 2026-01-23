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

    /** 项目名称输入框 */
    private final JBTextField nameField = new JBTextField();
    /** 平台选择下拉框 */
    private final ComboBox<ZaFridaPlatform> platformCombo = new ComboBox<>(ZaFridaPlatform.values());

    /**
     * 构造函数。
     * @param project 当前 IDE 项目（可为空）
     */
    public CreateZaFridaProjectDialog(@Nullable Project project) {
        super(project, true);
        setTitle("Create ZAFrida Project");
        init();
    }

    /**
     * 创建对话框中心面板。
     * @return 中心面板组件
     */
    @Override
    protected @Nullable JComponent createCenterPanel() {
        JPanel p = new JPanel(new GridLayout(2, 2, 8, 8));
        p.add(new JLabel("Name"));
        p.add(nameField);
        p.add(new JLabel("Platform"));
        p.add(platformCombo);
        return p;
    }

    /**
     * 获取项目名称。
     * @return 项目名称
     */
    public String getProjectName() {
        return nameField.getText().trim();
    }

    /**
     * 获取选择的平台。
     * @return ZaFridaPlatform
     */
    public ZaFridaPlatform getPlatform() {
        return (ZaFridaPlatform) platformCombo.getSelectedItem();
    }
}
