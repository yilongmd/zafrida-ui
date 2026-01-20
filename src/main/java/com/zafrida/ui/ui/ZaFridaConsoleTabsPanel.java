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
 */
public final class ZaFridaConsoleTabsPanel extends JPanel implements Disposable {

    private final JBTabbedPane tabbedPane;
    private final ZaFridaConsolePanel runConsolePanel;
    private final ZaFridaConsolePanel attachConsolePanel;

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

    public @NotNull ZaFridaConsolePanel getRunConsolePanel() {
        return runConsolePanel;
    }

    public @NotNull ZaFridaConsolePanel getAttachConsolePanel() {
        return attachConsolePanel;
    }

    public @NotNull ZaFridaConsolePanel getActiveConsolePanel() {
        return tabbedPane.getSelectedIndex() == 1 ? attachConsolePanel : runConsolePanel;
    }

    public void showRunConsole() {
        tabbedPane.setSelectedIndex(0);
    }

    public void showAttachConsole() {
        tabbedPane.setSelectedIndex(1);
    }

    public void clearActiveConsole() {
        getActiveConsolePanel().clear();
    }

    public void addTabChangeListener(@NotNull ChangeListener listener) {
        tabbedPane.addChangeListener(listener);
    }

    @Override
    public void dispose() {
        runConsolePanel.dispose();
        attachConsolePanel.dispose();
    }
}
