package com.zafrida.ui.ui;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.project.Project;
import com.intellij.ui.components.JBTabbedPane;
import com.intellij.util.ui.JBUI;
import com.zafrida.ui.session.ZaFridaSessionType;
import org.jetbrains.annotations.NotNull;

import javax.swing.JPanel;
import javax.swing.event.ChangeListener;
import java.awt.BorderLayout;

public final class ZaFridaConsoleTabsPanel extends JPanel implements Disposable {

    private static final int RUN_TAB_INDEX = 0;
    private static final int ATTACH_TAB_INDEX = 1;

    private final JBTabbedPane tabbedPane;
    private final ZaFridaConsolePanel runConsolePanel;
    private final ZaFridaConsolePanel attachConsolePanel;

    public ZaFridaConsoleTabsPanel(@NotNull Project project) {
        super(new BorderLayout());
        this.runConsolePanel = new ZaFridaConsolePanel(project);
        this.attachConsolePanel = new ZaFridaConsolePanel(project);

        this.tabbedPane = new JBTabbedPane();
        this.tabbedPane.setTabComponentInsets(JBUI.emptyInsets());
        this.tabbedPane.addTab("Run · Idle", runConsolePanel);
        this.tabbedPane.addTab("Attach · Idle", attachConsolePanel);

        add(tabbedPane, BorderLayout.CENTER);
    }

    public @NotNull ZaFridaConsolePanel getRunConsolePanel() {
        return runConsolePanel;
    }

    public @NotNull ZaFridaConsolePanel getAttachConsolePanel() {
        return attachConsolePanel;
    }

    public @NotNull ZaFridaConsolePanel getActiveConsolePanel() {
        if (tabbedPane.getSelectedIndex() == 1) {
            return attachConsolePanel;
        }
        return runConsolePanel;
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

    public void updateSessionState(@NotNull ZaFridaSessionType type,
                                   boolean running,
                                   boolean stopping) {
        String state = "Idle";
        if (stopping) {
            state = "Stopping";
        } else if (running) {
            state = "Running";
        }

        int tabIndex = RUN_TAB_INDEX;
        String sessionName = "Run";
        if (type == ZaFridaSessionType.ATTACH) {
            tabIndex = ATTACH_TAB_INDEX;
            sessionName = "Attach";
        }
        tabbedPane.setTitleAt(tabIndex, String.format("%s · %s", sessionName, state));
    }

    @Override
    public void dispose() {
        runConsolePanel.dispose();
        attachConsolePanel.dispose();
    }
}
