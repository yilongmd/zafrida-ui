package com.zafrida.ui.ui.components;

import com.zafrida.ui.frida.FridaConnectionMode;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;

import javax.swing.JComboBox;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConnectionModePanelTest {

    private static final class RecordingListener implements ConnectionModePanel.Listener {
        private final List<String> changes = new ArrayList<>();
        private final List<String> invalid = new ArrayList<>();

        @Override
        public void onConnectionChanged(@NotNull FridaConnectionMode mode, @NotNull String host, int port) {
            changes.add(String.format("%s %s:%s", mode.name(), host, port));
        }

        @Override
        public void onInvalidEndpoint(@NotNull String text) {
            invalid.add(text);
        }
    }

    @Test
    void programmaticUpdatesDoNotNotifyAndUsbHidesEndpoint() throws Exception {
        RecordingListener listener = new RecordingListener();
        List<Boolean> endpointVisible = new ArrayList<>();

        SwingUtilities.invokeAndWait(() -> {
            ConnectionModePanel panel = new ConnectionModePanel();
            panel.setListener(listener);
            panel.setConnection(FridaConnectionMode.USB, "127.0.0.1", 14725);
            endpointVisible.add(endpointCombo(panel).isVisible());
            panel.setEndpointPresets(List.of("127.0.0.1:14725", "192.168.1.20:27042"));
            panel.setConnection(FridaConnectionMode.GADGET, "127.0.0.1", 27042);
            endpointVisible.add(endpointCombo(panel).isVisible());
        });

        assertEquals(List.of(false, true), endpointVisible);
        assertTrue(listener.changes.isEmpty());
        assertTrue(listener.invalid.isEmpty());
    }

    @Test
    void userEditsCommitNormalizedEndpointAndRejectInvalidText() throws Exception {
        RecordingListener listener = new RecordingListener();
        List<String> committed = new ArrayList<>();

        SwingUtilities.invokeAndWait(() -> {
            ConnectionModePanel panel = new ConnectionModePanel();
            panel.setListener(listener);
            panel.setConnection(FridaConnectionMode.REMOTE, "127.0.0.1", 14725);
            JComboBox<?> endpoint = endpointCombo(panel);

            typeAndCommit(endpoint, "192.168.1.20:27042");
            committed.add(String.format("%s:%s", panel.getHost(), panel.getPort()));

            typeAndCommit(endpoint, "10.0.0.5");
            committed.add(String.format("%s:%s", panel.getHost(), panel.getPort()));

            typeAndCommit(endpoint, "10.0.0.5:99999");
            committed.add(String.format("%s:%s", panel.getHost(), panel.getPort()));
            committed.add(String.valueOf(endpoint.getEditor().getItem()));
        });

        assertEquals(List.of("192.168.1.20:27042", "10.0.0.5:27042", "10.0.0.5:27042", "10.0.0.5:27042"), committed);
        assertEquals(List.of("REMOTE 192.168.1.20:27042", "REMOTE 10.0.0.5:27042"), listener.changes);
        assertEquals(List.of("10.0.0.5:99999"), listener.invalid);
    }

    @Test
    void switchingModeKeepsEndpointAndNotifiesOnce() throws Exception {
        RecordingListener listener = new RecordingListener();

        SwingUtilities.invokeAndWait(() -> {
            ConnectionModePanel panel = new ConnectionModePanel();
            panel.setListener(listener);
            panel.setConnection(FridaConnectionMode.USB, "127.0.0.1", 14725);
            modeCombo(panel).setSelectedItem(FridaConnectionMode.GADGET);
        });

        assertEquals(List.of("GADGET 127.0.0.1:14725"), listener.changes);
    }

    @Test
    void temporaryFocusLossDoesNotCommitHalfTypedEndpoint() throws Exception {
        RecordingListener listener = new RecordingListener();
        List<String> committed = new ArrayList<>();

        SwingUtilities.invokeAndWait(() -> {
            ConnectionModePanel panel = new ConnectionModePanel();
            panel.setListener(listener);
            panel.setConnection(FridaConnectionMode.REMOTE, "127.0.0.1", 14725);
            JComboBox<?> endpoint = endpointCombo(panel);

            endpoint.getEditor().setItem("192.168.");
            fireFocusLost(endpoint, true);
            committed.add(String.format("%s:%s", panel.getHost(), panel.getPort()));

            endpoint.getEditor().setItem("192.168.1.20:27042");
            fireFocusLost(endpoint, false);
            committed.add(String.format("%s:%s", panel.getHost(), panel.getPort()));
        });

        assertEquals(List.of("127.0.0.1:14725", "192.168.1.20:27042"), committed);
        assertEquals(List.of("REMOTE 192.168.1.20:27042"), listener.changes);
    }

    private static void fireFocusLost(@NotNull JComboBox<?> endpoint, boolean temporary) {
        Component editor = endpoint.getEditor().getEditorComponent();
        FocusEvent event = new FocusEvent(editor, FocusEvent.FOCUS_LOST, temporary);
        for (FocusListener focusListener : editor.getFocusListeners()) {
            focusListener.focusLost(event);
        }
    }

    private static void typeAndCommit(@NotNull JComboBox<?> endpoint, @NotNull String text) {
        endpoint.getEditor().setItem(text);
        // 等价于在可编辑下拉里按回车。
        endpoint.actionPerformed(new java.awt.event.ActionEvent(endpoint.getEditor(), 0, ""));
    }

    private static @NotNull JComboBox<?> modeCombo(@NotNull ConnectionModePanel panel) {
        return comboAt(panel, 0);
    }

    private static @NotNull JComboBox<?> endpointCombo(@NotNull ConnectionModePanel panel) {
        return comboAt(panel, 1);
    }

    private static @NotNull JComboBox<?> comboAt(@NotNull ConnectionModePanel panel, int index) {
        List<JComboBox<?>> combos = new ArrayList<>();
        for (Component component : panel.getComponents()) {
            if (component instanceof JComboBox<?>) {
                combos.add((JComboBox<?>) component);
            }
        }
        return combos.get(index);
    }
}
