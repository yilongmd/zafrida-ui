package com.zafrida.ui.diagnostics;

import com.intellij.icons.AllIcons;
import com.intellij.ui.components.ActionLink;
import com.intellij.ui.components.JBLabel;
import com.intellij.util.ui.AsyncProcessIcon;
import com.intellij.util.ui.JBUI;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Locale;

public final class EnvironmentDoctorItemPanel extends JPanel {

    private static final String CARD_SPINNER = "SPINNER";
    private static final String CARD_ICON = "ICON";

    private final ZaFridaDiagnosticItem item;
    private final AsyncProcessIcon spinner;
    private final JLabel statusIconLabel;
    private final CardLayout statusLayout;
    private final JPanel statusPanel;

    private final JBLabel titleLabel;
    private final JBLabel descLabel;
    private final JBLabel statusLabel;
    private final JBLabel tipLabel;
    private final ActionLink skipLink;

    public EnvironmentDoctorItemPanel(@NotNull ZaFridaDiagnosticItem item) {
        super(new BorderLayout(JBUI.scale(8), 0));
        this.item = item;

        statusLayout = new CardLayout();
        statusPanel = new JPanel(statusLayout);
        statusPanel.setBorder(JBUI.Borders.empty(0, 0, 0, 6));

        spinner = new AsyncProcessIcon("doctor-check");
        statusIconLabel = new JLabel();
        statusPanel.add(spinner, CARD_SPINNER);
        statusPanel.add(statusIconLabel, CARD_ICON);

        titleLabel = new JBLabel(item.getTitle());
        Font base = titleLabel.getFont();
        titleLabel.setFont(base.deriveFont(Font.BOLD));

        descLabel = new JBLabel(wrapSmall(item.getDescription()));

        statusLabel = new JBLabel();
        tipLabel = new JBLabel();

        skipLink = new ActionLink("Skip (跳过)", new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                handleSkip();
            }
        });

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.add(titleLabel);
        content.add(descLabel);
        content.add(statusLabel);
        content.add(tipLabel);

        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        right.add(skipLink);

        setBorder(JBUI.Borders.empty(6, 8));
        add(statusPanel, BorderLayout.WEST);
        add(content, BorderLayout.CENTER);
        add(right, BorderLayout.EAST);

        refresh();
    }

    public void refresh() {
        ZaFridaDiagnosticStatus status = item.getStatus();
        updateStatusIcon(status);
        updateStatusText(status, item.getMessage());
        updateTip(item.getTip());
        updateSkipEnabled(status);
    }

    private void updateStatusIcon(@NotNull ZaFridaDiagnosticStatus status) {
        if (status == ZaFridaDiagnosticStatus.RUNNING) {
            statusLayout.show(statusPanel, CARD_SPINNER);
            return;
        }

        statusLayout.show(statusPanel, CARD_ICON);
        statusIconLabel.setIcon(resolveIcon(status));
    }

    private void updateStatusText(@NotNull ZaFridaDiagnosticStatus status, @Nullable String message) {
        String statusText = resolveStatusText(status);
        String finalText;
        if (ZaStrUtil.isNotBlank(message)) {
            if (isHtml(message)) {
                String body = stripHtmlWrapper(message);
                finalText = String.format("<html>%s: %s</html>", statusText, body);
            } else {
                finalText = String.format("%s: %s", statusText, message);
            }
        } else {
            finalText = statusText;
        }
        statusLabel.setText(finalText);
    }

    private void updateTip(@Nullable String tip) {
        if (ZaStrUtil.isBlank(tip)) {
            tipLabel.setText("");
            return;
        }
        tipLabel.setText(wrapSmall(tip));
    }

    private void updateSkipEnabled(@NotNull ZaFridaDiagnosticStatus status) {
        boolean enabled = status == ZaFridaDiagnosticStatus.PENDING || status == ZaFridaDiagnosticStatus.RUNNING;
        skipLink.setEnabled(enabled);
    }

    private Icon resolveIcon(@NotNull ZaFridaDiagnosticStatus status) {
        if (status == ZaFridaDiagnosticStatus.SUCCESS) {
            return AllIcons.General.InspectionsOK;
        }
        if (status == ZaFridaDiagnosticStatus.FAILED) {
            return AllIcons.General.Error;
        }
        if (status == ZaFridaDiagnosticStatus.SKIPPED) {
            return AllIcons.General.Warning;
        }
        return AllIcons.General.BalloonInformation;
    }

    private String resolveStatusText(@NotNull ZaFridaDiagnosticStatus status) {
        if (status == ZaFridaDiagnosticStatus.RUNNING) {
            return "Running (检测中)";
        }
        if (status == ZaFridaDiagnosticStatus.SUCCESS) {
            return "Passed (已通过)";
        }
        if (status == ZaFridaDiagnosticStatus.FAILED) {
            return "Failed (失败)";
        }
        if (status == ZaFridaDiagnosticStatus.SKIPPED) {
            return "Skipped (已跳过)";
        }
        return "Pending (等待中)";
    }

    private void handleSkip() {
        item.requestSkip();
        item.updateStatus(ZaFridaDiagnosticStatus.SKIPPED, null, item.getTip());
        refresh();
    }

    private String wrapSmall(@NotNull String text) {
        return String.format("<html><small style='color:gray'>%s</small></html>", text);
    }

    private boolean isHtml(@NotNull String text) {
        String lower = text.trim().toLowerCase(Locale.ROOT);
        return lower.startsWith("<html>");
    }

    private String stripHtmlWrapper(@NotNull String text) {
        String value = text.trim();
        String lower = value.toLowerCase(Locale.ROOT);
        if (lower.startsWith("<html>")) {
            value = value.substring(6);
            lower = value.toLowerCase(Locale.ROOT);
        }
        if (lower.endsWith("</html>")) {
            value = value.substring(0, value.length() - 7);
        }
        return value;
    }
}
