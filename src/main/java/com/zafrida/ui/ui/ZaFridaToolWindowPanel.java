package com.zafrida.ui.ui;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.project.Project;
import com.intellij.ui.JBSplitter;

import javax.swing.JPanel;
import java.awt.BorderLayout;
/**
 * [UI组件] 备用主面板容器。
 * <p>
 * 使用 {@link JBSplitter} 将界面划分为：
 * <ul>
 * <li>Top: 左右分割的 Run Panel 和 Template Panel。</li>
 * <li>Bottom: Console Panel。</li>
 * </ul>
 * <strong>注意：</strong> 此类目前可能作为特定的视图模式使用，标准模式下通常使用 {@link ZaFridaMainToolWindow}。
 */
public final class ZaFridaToolWindowPanel extends JPanel implements Disposable {

    /** 控制台选项卡面板 */
    private final ZaFridaConsoleTabsPanel consoleTabsPanel;
    /** 模板面板 */
    private final ZaFridaTemplatePanel templatePanel;
    /** Run 面板 */
    private final ZaFridaRunPanel runPanel;

    /**
     * 构造函数。
     * @param project 当前 IDE 项目
     */
    public ZaFridaToolWindowPanel(Project project) {
        super(new BorderLayout());

        // consoleTabsPanel 必须先初始化，因为 templatePanel/runPanel 需要它
        // consoleTabsPanel 必须先初始化，因为 templatePanel/runPanel 依赖它
        this.consoleTabsPanel = new ZaFridaConsoleTabsPanel(project);
        this.templatePanel = new ZaFridaTemplatePanel(project, consoleTabsPanel.getRunConsolePanel());
        this.runPanel = new ZaFridaRunPanel(project, consoleTabsPanel, templatePanel);

        // top: run + templates
        // 顶部：Run + Templates
        JBSplitter topSplitter = new JBSplitter(false, 0.55f);
        topSplitter.setFirstComponent(runPanel);
        topSplitter.setSecondComponent(templatePanel);

        // main: (top) + (bottom console)
        // 主区域：（上半部分）+（底部控制台）
        JBSplitter mainSplitter = new JBSplitter(true, 0.60f);
        mainSplitter.setFirstComponent(topSplitter);
        mainSplitter.setSecondComponent(consoleTabsPanel);

        add(mainSplitter, BorderLayout.CENTER);
    }

    /**
     * 释放资源。
     */
    @Override
    public void dispose() {
        runPanel.dispose();
        templatePanel.dispose();
        consoleTabsPanel.dispose();
    }
}
