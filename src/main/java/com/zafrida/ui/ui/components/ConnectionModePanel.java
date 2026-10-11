package com.zafrida.ui.ui.components;

import com.intellij.openapi.ui.ComboBox;
import com.intellij.util.ui.JBUI;
import com.zafrida.ui.frida.FridaConnectionMode;
import com.zafrida.ui.util.ZaFridaNetUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.util.List;

/**
 * 连接模式行：模式下拉 + Remote/Gadget 端点（host:port，可编辑下拉）。
 * 只负责采集与校验，不读写配置；设备选择不在这里。
 */
public final class ConnectionModePanel extends JPanel {

    public interface Listener {
        void onConnectionChanged(@NotNull FridaConnectionMode mode, @NotNull String host, int port);

        void onInvalidEndpoint(@NotNull String text);
    }

    private static final String ENDPOINT_PROTOTYPE = "255.255.255.255:65535";

    private final ComboBox<FridaConnectionMode> modeCombo = new ComboBox<>(FridaConnectionMode.values());
    private final ComboBox<String> endpointCombo = new ComboBox<>();

    private @Nullable Listener listener;
    private boolean updating;
    private @NotNull String committedHost = ZaFridaNetUtil.LOOPBACK_HOST;
    private int committedPort = ZaFridaNetUtil.DEFAULT_FRIDA_PORT;

    public ConnectionModePanel() {
        super(new BorderLayout(JBUI.scale(6), 0));

        modeCombo.setToolTipText("How Frida reaches the target: USB device, remote frida-server, or Gadget");
        endpointCombo.setEditable(true);
        endpointCombo.setPrototypeDisplayValue(ENDPOINT_PROTOTYPE);
        endpointCombo.setToolTipText("Frida endpoint host:port. Press Enter to apply.");
        Dimension minimumSize = endpointCombo.getMinimumSize();
        endpointCombo.setMinimumSize(new Dimension(JBUI.scale(100), minimumSize.height));

        add(modeCombo, BorderLayout.WEST);
        add(endpointCombo, BorderLayout.CENTER);

        modeCombo.addActionListener(event -> onModeSelected());
        endpointCombo.addActionListener(event -> commitEndpoint());
        // 可编辑下拉只在回车时触发 action，失焦也要提交，否则输入后直接点 Run 会用到旧端点。
        Component editorComponent = endpointCombo.getEditor().getEditorComponent();
        editorComponent.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent event) {
                // 切到别的窗口是临时失焦，文本可能只输了一半，不能当作提交。
                if (event.isTemporary()) {
                    return;
                }
                commitEndpoint();
            }
        });

        updateEndpointVisibility();
    }

    public void setListener(@Nullable Listener listener) {
        this.listener = listener;
    }

    /** 程序化回填，不触发 Listener。 */
    public void setConnection(@NotNull FridaConnectionMode mode, @NotNull String host, int port) {
        updating = true;
        try {
            committedHost = host;
            committedPort = port;
            modeCombo.setSelectedItem(mode);
            endpointCombo.setSelectedItem(ZaFridaNetUtil.formatHostPort(host, port));
            updateEndpointVisibility();
        } finally {
            updating = false;
        }
    }

    /** 替换候选端点，保留当前已提交的端点文本。 */
    public void setEndpointPresets(@NotNull List<String> presets) {
        updating = true;
        try {
            endpointCombo.removeAllItems();
            for (String preset : presets) {
                endpointCombo.addItem(preset);
            }
            endpointCombo.setSelectedItem(ZaFridaNetUtil.formatHostPort(committedHost, committedPort));
        } finally {
            updating = false;
        }
    }

    public @NotNull FridaConnectionMode getMode() {
        FridaConnectionMode mode = (FridaConnectionMode) modeCombo.getSelectedItem();
        if (mode == null) {
            return FridaConnectionMode.USB;
        }
        return mode;
    }

    public @NotNull String getHost() {
        return committedHost;
    }

    public int getPort() {
        return committedPort;
    }

    private void onModeSelected() {
        if (updating) {
            return;
        }
        updateEndpointVisibility();
        fireConnectionChanged();
    }

    private void commitEndpoint() {
        if (updating) {
            return;
        }
        String text = currentEndpointText();
        ZaFridaNetUtil.HostPort endpoint = ZaFridaNetUtil.parseHostPort(text, committedPort);
        if (endpoint == null) {
            restoreCommittedEndpoint();
            if (listener != null && !text.isEmpty()) {
                listener.onInvalidEndpoint(text);
            }
            return;
        }
        boolean changed = !endpoint.getHost().equals(committedHost) || endpoint.getPort() != committedPort;
        committedHost = endpoint.getHost();
        committedPort = endpoint.getPort();
        // 把 "host" 之类的简写规范化成完整的 host:port。
        restoreCommittedEndpoint();
        if (changed) {
            fireConnectionChanged();
        }
    }

    private @NotNull String currentEndpointText() {
        Object item = endpointCombo.getEditor().getItem();
        if (item == null) {
            return "";
        }
        return item.toString().trim();
    }

    private void restoreCommittedEndpoint() {
        updating = true;
        try {
            endpointCombo.setSelectedItem(ZaFridaNetUtil.formatHostPort(committedHost, committedPort));
        } finally {
            updating = false;
        }
    }

    private void updateEndpointVisibility() {
        endpointCombo.setVisible(getMode() != FridaConnectionMode.USB);
        revalidate();
        repaint();
    }

    private void fireConnectionChanged() {
        if (listener != null) {
            listener.onConnectionChanged(getMode(), committedHost, committedPort);
        }
    }
}
