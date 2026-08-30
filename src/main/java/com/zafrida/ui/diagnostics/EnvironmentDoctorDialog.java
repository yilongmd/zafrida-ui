package com.zafrida.ui.diagnostics;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.DialogWrapper;
import com.intellij.ui.components.JBLabel;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.util.ui.JBUI;
import com.zafrida.ui.frida.FridaDevice;
import com.zafrida.ui.util.ZaFridaNotifier;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

public final class EnvironmentDoctorDialog extends DialogWrapper {

    private final @NotNull Project project;
    private final @NotNull ZaFridaDiagnosticsService diagnosticsService;
    private final @NotNull Supplier<FridaDevice> deviceSupplier;

    private final Map<String, EnvironmentDoctorItemPanel> itemPanels = new LinkedHashMap<>();
    private List<ZaFridaDiagnosticItem> items;

    private JBLabel summaryLabel;
    private boolean running = false;
    private Action runAgainAction;

    public EnvironmentDoctorDialog(@NotNull Project project,
                                   @NotNull Supplier<FridaDevice> deviceSupplier) {
        super(project, true);
        this.project = project;
        this.deviceSupplier = deviceSupplier;
        this.diagnosticsService = ApplicationManager.getApplication().getService(ZaFridaDiagnosticsService.class);
        this.items = diagnosticsService.createDefaultItems();

        setTitle("Environment Doctor");
        setSize(720, 520);
        setOKButtonText("Close");

        init();

        ApplicationManager.getApplication().invokeLater(this::startDiagnostics);
    }

    @Override
    protected @Nullable JComponent createCenterPanel() {
        JPanel root = new JPanel(new BorderLayout(0, JBUI.scale(8)));
        root.setBorder(JBUI.Borders.empty(10));

        JBLabel header = new JBLabel(buildHeaderHtml());

        JPanel listPanel = new JPanel();
        listPanel.setLayout(new BoxLayout(listPanel, BoxLayout.Y_AXIS));
        listPanel.setBorder(JBUI.Borders.empty(4, 0));

        itemPanels.clear();
        for (ZaFridaDiagnosticItem item : items) {
            EnvironmentDoctorItemPanel panel = new EnvironmentDoctorItemPanel(item);
            itemPanels.put(item.getId(), panel);
            listPanel.add(panel);
            listPanel.add(Box.createVerticalStrut(JBUI.scale(6)));
        }

        JBScrollPane scrollPane = new JBScrollPane(listPanel);
        scrollPane.setBorder(JBUI.Borders.empty());

        summaryLabel = new JBLabel("Preparing diagnostics... (准备诊断...)");

        root.add(header, BorderLayout.NORTH);
        root.add(scrollPane, BorderLayout.CENTER);
        root.add(summaryLabel, BorderLayout.SOUTH);

        return root;
    }

    @Override
    protected Action @NotNull [] createActions() {
        runAgainAction = new DialogWrapperAction("Run Again") {
            @Override
            protected void doAction(@NotNull java.awt.event.ActionEvent e) {
                startDiagnostics();
            }
        };

        return new Action[]{runAgainAction, getOKAction()};
    }

    private void startDiagnostics() {
        if (running) {
            return;
        }

        running = true;
        if (runAgainAction != null) {
            runAgainAction.setEnabled(false);
        }

        for (ZaFridaDiagnosticItem item : items) {
            item.reset();
            refreshItem(item);
        }
        updateSummary(items);

        @Nullable FridaDevice device = deviceSupplier.get();
        diagnosticsService.runDiagnostics(project, device, items, new ZaFridaDiagnosticsListener() {
            @Override
            public void onItemUpdated(@NotNull ZaFridaDiagnosticItem item) {
                refreshItem(item);
                updateSummary(items);
            }

            @Override
            public void onAllCompleted(@NotNull List<ZaFridaDiagnosticItem> items) {
                running = false;
                if (runAgainAction != null) {
                    runAgainAction.setEnabled(true);
                }
                updateSummary(items);
                notifyIfFailed(items);
            }
        });
    }

    private void refreshItem(@NotNull ZaFridaDiagnosticItem item) {
        EnvironmentDoctorItemPanel panel = itemPanels.get(item.getId());
        if (panel == null) {
            return;
        }
        panel.refresh();
    }

    private void updateSummary(@NotNull List<ZaFridaDiagnosticItem> items) {
        int success = 0;
        int failed = 0;
        int skipped = 0;
        int runningCount = 0;
        int pending = 0;

        for (ZaFridaDiagnosticItem item : items) {
            ZaFridaDiagnosticStatus status = item.getStatus();
            if (status == ZaFridaDiagnosticStatus.SUCCESS) {
                success++;
            } else if (status == ZaFridaDiagnosticStatus.FAILED) {
                failed++;
            } else if (status == ZaFridaDiagnosticStatus.SKIPPED) {
                skipped++;
            } else if (status == ZaFridaDiagnosticStatus.RUNNING) {
                runningCount++;
            } else if (status == ZaFridaDiagnosticStatus.PENDING) {
                pending++;
            }
        }

        String text;
        if (runningCount > 0) {
            text = String.format("Running... Completed %s items (诊断中... 已完成 %s 项)", success, success);
        } else if (pending > 0) {
            text = String.format("Running... Completed %s items (诊断中... 已完成 %s 项)", success, success);
        } else {
            text = String.format(
                    "Done: Success %s, Failed %s, Skipped %s (完成：成功 %s，失败 %s，跳过 %s)",
                    success,
                    failed,
                    skipped,
                    success,
                    failed,
                    skipped
            );
        }
        summaryLabel.setText(text);
    }

    private void notifyIfFailed(@NotNull List<ZaFridaDiagnosticItem> items) {
        int failed = 0;
        for (ZaFridaDiagnosticItem item : items) {
            if (item.getStatus() == ZaFridaDiagnosticStatus.FAILED) {
                failed++;
            }
        }

        if (failed > 0) {
            ZaFridaNotifier.warn(
                    project,
                    "Environment Doctor",
                    String.format("Found %s issues, please check details. (发现 %s 个问题，请查看详情。)", failed, failed)
            );
        }
    }

    private static @NotNull String buildHeaderHtml() {
        return "<html><b>Environment Doctor</b><br/><small style='color:gray'>Check dependencies step by step, recommended for first run. (逐项检查环境依赖，建议首次使用先跑一遍。)</small></html>";
    }
}
