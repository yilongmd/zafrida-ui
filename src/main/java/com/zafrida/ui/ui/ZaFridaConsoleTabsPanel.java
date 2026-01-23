package com.zafrida.ui.ui;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.project.Project;
import com.intellij.ui.components.JBTabbedPane;
import com.intellij.util.ui.JBUI;
import org.jetbrains.annotations.NotNull;

import javax.swing.JPanel;
import javax.swing.event.ChangeListener;
import java.awt.BorderLayout;

/**
 * [UI Component] Run/Attach console container with JetBrains tabs.
 * [UI组件] Run/Attach 控制台容器（JetBrains 选项卡）。
 */
public final class ZaFridaConsoleTabsPanel extends JPanel implements Disposable {

    /** 选项卡容器 */
    private final JBTabbedPane tabbedPane;
    /** Run 控制台面板 */
    private final ZaFridaConsolePanel runConsolePanel;
    /** Attach 控制台面板 */
    private final ZaFridaConsolePanel attachConsolePanel;

    /**
     * 构造函数。
     * @param project 当前 IDE 项目
     */
    public ZaFridaConsoleTabsPanel(@NotNull Project project) {
        super(new BorderLayout());
        this.runConsolePanel = new ZaFridaConsolePanel(project);
        this.attachConsolePanel = new ZaFridaConsolePanel(project);

        this.tabbedPane = new JBTabbedPane();
        this.tabbedPane.setTabComponentInsets(JBUI.emptyInsets());
        this.tabbedPane.addTab("Run", runConsolePanel);
        this.tabbedPane.addTab("Attach", attachConsolePanel);

        add(tabbedPane, BorderLayout.CENTER);
    }

    /**
     * 获取 Run 控制台面板。
     * @return Run 控制台
     */
    public @NotNull ZaFridaConsolePanel getRunConsolePanel() {
        return runConsolePanel;
    }

    /**
     * 获取 Attach 控制台面板。
     * @return Attach 控制台
     */
    public @NotNull ZaFridaConsolePanel getAttachConsolePanel() {
        return attachConsolePanel;
    }

    /**
     * 获取当前激活的控制台面板。
     * @return 控制台面板
     */
    public @NotNull ZaFridaConsolePanel getActiveConsolePanel() {
        return tabbedPane.getSelectedIndex() == 1 ? attachConsolePanel : runConsolePanel;
    }

    /**
     * 切换到 Run 控制台。
     */
    public void showRunConsole() {
        tabbedPane.setSelectedIndex(0);
    }

    /**
     * 切换到 Attach 控制台。
     */
    public void showAttachConsole() {
        tabbedPane.setSelectedIndex(1);
    }

    /**
     * 清空当前控制台内容。
     */
    public void clearActiveConsole() {
        getActiveConsolePanel().clear();
    }

    /**
     * 添加选项卡切换监听器。
     * @param listener 监听器
     */
    public void addTabChangeListener(@NotNull ChangeListener listener) {
        tabbedPane.addChangeListener(listener);
    }

    /**
     * 释放资源。
     */
    @Override
    public void dispose() {
        runConsolePanel.dispose();
        attachConsolePanel.dispose();
    }
}
