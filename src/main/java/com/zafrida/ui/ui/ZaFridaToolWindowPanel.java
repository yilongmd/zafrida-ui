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

    private final ZaFridaConsolePanel consolePanel;
    private final ZaFridaTemplatePanel templatePanel;
    private final ZaFridaRunPanel runPanel;

    public ZaFridaToolWindowPanel(Project project) {
        super(new BorderLayout());

        // consolePanel 必须先初始化，因为 templatePanel 需要它
        this.consolePanel = new ZaFridaConsolePanel(project);
        this.templatePanel = new ZaFridaTemplatePanel(project, consolePanel);
        this.runPanel = new ZaFridaRunPanel(project, consolePanel, templatePanel);

        // top: run + templates
        JBSplitter topSplitter = new JBSplitter(false, 0.55f);
        topSplitter.setFirstComponent(runPanel);
        topSplitter.setSecondComponent(templatePanel);

        // main: (top) + (bottom console)
        JBSplitter mainSplitter = new JBSplitter(true, 0.60f);
        mainSplitter.setFirstComponent(topSplitter);
        mainSplitter.setSecondComponent(consolePanel);

        add(mainSplitter, BorderLayout.CENTER);
    }

    @Override
    public void dispose() {
        runPanel.dispose();
        templatePanel.dispose();
        consolePanel.dispose();
    }
}