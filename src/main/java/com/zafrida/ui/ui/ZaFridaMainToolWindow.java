package com.zafrida.ui.ui;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.Disposer;
import com.intellij.openapi.util.IconLoader;
import com.intellij.ui.components.JBTabbedPane;
import com.intellij.icons.AllIcons;
import com.intellij.util.ui.JBUI;
import org.jetbrains.annotations.NotNull;

import javax.swing.*;
import java.awt.*;
/**
 * [UI 根组件] ZAFrida ToolWindow 的顶层容器。
 * <p>
 * <strong>布局结构：</strong>
 * <ul>
 * <li><strong>Header:</strong> 顶部工具栏（创建项目、设置、全局运行控制）。</li>
 * <li><strong>TabPane:</strong> 中间选项卡（Run Panel / Template Panel）。</li>
 * <li><strong>Console:</strong> 底部日志控制台（Run/Attach 分离）。</li>
 * </ul>
 * <strong>职责：</strong> 负责各子组件的初始化、布局组装及全局按钮事件的分发。
 */
public final class ZaFridaMainToolWindow extends JPanel implements Disposable {

    private final JBTabbedPane tabbedPane;
    private final ZaFridaRunPanel runPanel;
    private final ZaFridaTemplatePanel templatePanel;
    private final ZaFridaConsoleTabsPanel consoleTabsPanel;

    public ZaFridaMainToolWindow(@NotNull Project project) {
        super(new BorderLayout());

        this.consoleTabsPanel = new ZaFridaConsoleTabsPanel(project);
        this.templatePanel = new ZaFridaTemplatePanel(project, consoleTabsPanel.getRunConsolePanel());
        this.runPanel = new ZaFridaRunPanel(project, consoleTabsPanel, templatePanel);

        Disposer.register(this, consoleTabsPanel);
        Disposer.register(this, runPanel);

        tabbedPane = new JBTabbedPane();
        tabbedPane.setTabComponentInsets(JBUI.emptyInsets());

        tabbedPane.addTab("Run", runPanel);
        tabbedPane.addTab("Templates", templatePanel);

        JPanel header = buildHeader();
        JPanel topContainer = new JPanel(new BorderLayout());
        topContainer.add(header, BorderLayout.NORTH);
        topContainer.add(tabbedPane, BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(topContainer);
        splitPane.setBottomComponent(consoleTabsPanel);
        splitPane.setResizeWeight(0.6);
        splitPane.setDividerSize(JBUI.scale(4));
        splitPane.setBorder(JBUI.Borders.empty());

        add(splitPane, BorderLayout.CENTER);
    }

    public @NotNull ZaFridaConsoleTabsPanel getConsoleTabsPanel() {
        return consoleTabsPanel;
    }

    public @NotNull ZaFridaRunPanel getRunPanel() {
        return runPanel;
    }

    public @NotNull ZaFridaTemplatePanel getTemplatePanel() {
        return templatePanel;
    }

    private JPanel buildHeader() {
        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setBorder(JBUI.Borders.empty(6, 8));

        JPanel projectRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton newProjectBtn = new JButton("New Project");
        newProjectBtn.setIcon(AllIcons.Actions.NewFolder);
        newProjectBtn.addActionListener(e -> runPanel.openNewProjectDialog());

        JButton projectSettingsBtn = new JButton("Project Settings");
        projectSettingsBtn.setIcon(AllIcons.General.Settings);
        projectSettingsBtn.addActionListener(e -> runPanel.openProjectSettingsDialog());

        JButton globalSettingsBtn = new JButton("Global Settings");
        globalSettingsBtn.setIcon(AllIcons.General.Settings);
        globalSettingsBtn.addActionListener(e -> runPanel.openGlobalSettingsDialog());

        JButton languageToggleBtn = new JButton(
                IconLoader.getIcon("/META-INF/icons/lang-toggle.svg", ZaFridaMainToolWindow.class)
        );
        languageToggleBtn.setToolTipText("中文 / English");
        languageToggleBtn.addActionListener(e -> runPanel.showLanguageToggleMessage());

        projectRow.add(newProjectBtn);
        projectRow.add(projectSettingsBtn);
        projectRow.add(globalSettingsBtn);
        projectRow.add(languageToggleBtn);

        JPanel runRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        JButton runBtn = new JButton("Run");
        runBtn.setIcon(AllIcons.Actions.Execute);
        runBtn.addActionListener(e -> runPanel.triggerRun());

        JButton stopBtn = new JButton("Stop");
        stopBtn.setIcon(AllIcons.Actions.Suspend);
        stopBtn.addActionListener(e -> runPanel.triggerStop());

        JButton forceStopBtn = new JButton("S App");
        forceStopBtn.setIcon(AllIcons.Actions.Cancel);
        forceStopBtn.addActionListener(e -> runPanel.triggerForceStop());

        JButton openAppBtn = new JButton("S App");
        openAppBtn.setIcon(AllIcons.Actions.Execute);
        openAppBtn.addActionListener(e -> runPanel.triggerOpenApp());

        JButton clearConsoleBtn = new JButton("Clear Console");
        clearConsoleBtn.setIcon(AllIcons.Actions.ClearCash);
        clearConsoleBtn.addActionListener(e -> runPanel.triggerClearConsole());

        runPanel.bindExternalRunStopButtons(runBtn, stopBtn);

        runRow.add(runBtn);
        runRow.add(stopBtn);
        runRow.add(forceStopBtn);
        runRow.add(openAppBtn);
        runRow.add(clearConsoleBtn);

        header.add(projectRow);
        header.add(Box.createVerticalStrut(JBUI.scale(4)));
        header.add(runRow);

        return header;
    }

    @Override
    public void dispose() {
        // children disposed via Disposer
    }
}
