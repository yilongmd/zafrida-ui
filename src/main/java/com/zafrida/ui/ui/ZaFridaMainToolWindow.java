package com.zafrida.ui.ui;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.Disposer;
import com.intellij.ui.components.JBTabbedPane;
import com.intellij.util.ui.JBUI;
import org.jetbrains.annotations.NotNull;

import javax.swing.*;
import java.awt.*;

public final class ZaFridaMainToolWindow extends JPanel implements Disposable {

    private final JBTabbedPane tabbedPane;
    private final ZaFridaRunPanel runPanel;
    private final ZaFridaTemplatePanel templatePanel;
    private final ZaFridaConsolePanel consolePanel;

    public ZaFridaMainToolWindow(@NotNull Project project) {
        super(new BorderLayout());

        this.consolePanel = new ZaFridaConsolePanel(project);
        this.templatePanel = new ZaFridaTemplatePanel(project, consolePanel);
        this.runPanel = new ZaFridaRunPanel(project, consolePanel, templatePanel);

        Disposer.register(this, consolePanel);
        Disposer.register(this, runPanel);

        tabbedPane = new JBTabbedPane();
        tabbedPane.setTabComponentInsets(JBUI.emptyInsets());

        tabbedPane.addTab("Run", runPanel);
        tabbedPane.addTab("Templates", templatePanel);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        splitPane.setTopComponent(tabbedPane);
        splitPane.setBottomComponent(consolePanel);
        splitPane.setResizeWeight(0.6);
        splitPane.setDividerSize(JBUI.scale(4));
        splitPane.setBorder(JBUI.Borders.empty());

        add(splitPane, BorderLayout.CENTER);
    }

    public @NotNull ZaFridaConsolePanel getConsolePanel() {
        return consolePanel;
    }

    public @NotNull ZaFridaRunPanel getRunPanel() {
        return runPanel;
    }

    public @NotNull ZaFridaTemplatePanel getTemplatePanel() {
        return templatePanel;
    }

    @Override
    public void dispose() {
        // children disposed via Disposer
    }
}