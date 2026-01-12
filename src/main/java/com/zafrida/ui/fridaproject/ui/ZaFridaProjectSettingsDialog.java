package com.zafrida.ui.fridaproject.ui;

import com.intellij.icons.AllIcons;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.ComboBox;
import com.intellij.openapi.ui.DialogWrapper;
import com.intellij.openapi.ui.Messages;
import com.zafrida.ui.frida.FridaCliService;
import com.zafrida.ui.frida.FridaDevice;
import com.zafrida.ui.frida.FridaProcess;
import com.zafrida.ui.frida.FridaProcessScope;
import com.zafrida.ui.fridaproject.ZaFridaFridaProject;
import com.zafrida.ui.fridaproject.ZaFridaProjectConfig;
import com.zafrida.ui.fridaproject.ZaFridaProjectManager;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.List;
import java.util.function.Supplier;

public final class ZaFridaProjectSettingsDialog extends DialogWrapper {

    private final Project project;
    private final ZaFridaProjectManager projectManager;
    private final FridaCliService fridaCliService;
    private final Supplier<FridaDevice> deviceSupplier;

    private final ComboBox<FridaProcessScope> scopeCombo = new ComboBox<>(FridaProcessScope.values());
    private final ComboBox<String> targetCombo = new ComboBox<>();
    private final JButton refreshTargetsBtn = new JButton("Refresh");

    private @Nullable ZaFridaFridaProject activeProject;

    public ZaFridaProjectSettingsDialog(@NotNull Project project,
                                        @NotNull ZaFridaProjectManager projectManager,
                                        @NotNull FridaCliService fridaCliService,
                                        @NotNull Supplier<FridaDevice> deviceSupplier) {
        super(project, true);
        this.project = project;
        this.projectManager = projectManager;
        this.fridaCliService = fridaCliService;
        this.deviceSupplier = deviceSupplier;
        refreshTargetsBtn.setIcon(AllIcons.Actions.Refresh);
        setTitle("ZAFrida Project Settings");
        setOKButtonText("Save");
        init();
        loadFromProject();
        bindActions();
    }

    @Override
    protected @Nullable JComponent createCenterPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints labelC = new GridBagConstraints();
        labelC.gridx = 0;
        labelC.insets = new Insets(6, 8, 6, 8);
        labelC.anchor = GridBagConstraints.WEST;

        GridBagConstraints fieldC = new GridBagConstraints();
        fieldC.gridx = 1;
        fieldC.weightx = 1;
        fieldC.fill = GridBagConstraints.HORIZONTAL;
        fieldC.insets = new Insets(6, 8, 6, 8);

        int row = 0;
        labelC.gridy = row;
        fieldC.gridy = row;
        panel.add(new JLabel("Scope"), labelC);
        panel.add(scopeCombo, fieldC);

        row++;
        labelC.gridy = row;
        fieldC.gridy = row;
        panel.add(new JLabel("Target (package/bundle)"), labelC);
        panel.add(buildTargetRow(), fieldC);

        return panel;
    }

    private JPanel buildTargetRow() {
        JPanel row = new JPanel(new BorderLayout(8, 0));
        targetCombo.setEditable(true);
        targetCombo.setPrototypeDisplayValue("com.example.app.package");
        row.add(targetCombo, BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actions.add(refreshTargetsBtn);
        row.add(actions, BorderLayout.EAST);
        return row;
    }

    private void bindActions() {
        refreshTargetsBtn.addActionListener(e -> refreshTargets());
        scopeCombo.addActionListener(e -> refreshTargets());
    }

    private void loadFromProject() {
        activeProject = projectManager.getActiveProject();
        if (activeProject == null) {
            scopeCombo.setEnabled(false);
            targetCombo.setEnabled(false);
            refreshTargetsBtn.setEnabled(false);
            return;
        }

        ZaFridaProjectConfig cfg = projectManager.loadProjectConfig(activeProject);
        scopeCombo.setSelectedItem(cfg.processScope);
        setTargetText(cfg.lastTarget);
        refreshTargets();
    }

    private void refreshTargets() {
        FridaDevice device = deviceSupplier.get();
        if (device == null) {
            return;
        }
        FridaProcessScope scope = (FridaProcessScope) scopeCombo.getSelectedItem();
        if (scope == null) scope = FridaProcessScope.RUNNING_APPS;

        refreshTargetsBtn.setEnabled(false);
        FridaProcessScope finalScope = scope;
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            try {
                List<FridaProcess> processes = fridaCliService.listProcesses(project, device, finalScope);
                ApplicationManager.getApplication().invokeLater(() -> {
                    targetCombo.removeAllItems();
                    for (FridaProcess p : processes) {
                        String label = targetLabel(p);
                        if (label != null && !label.isBlank()) {
                            targetCombo.addItem(label);
                        }
                    }
                    refreshTargetsBtn.setEnabled(true);
                });
            } catch (Throwable t) {
                ApplicationManager.getApplication().invokeLater(() -> {
                    refreshTargetsBtn.setEnabled(true);
                    Messages.showWarningDialog(project, "Load targets failed: " + t.getMessage(), "ZAFrida");
                });
            }
        });
    }

    @Override
    protected void doOKAction() {
        if (activeProject == null) {
            super.doOKAction();
            return;
        }
        FridaProcessScope scope = (FridaProcessScope) scopeCombo.getSelectedItem();
        String target = getTargetText();

        projectManager.updateProjectConfig(activeProject, cfg -> {
            cfg.processScope = scope != null ? scope : FridaProcessScope.RUNNING_APPS;
            cfg.lastTarget = target.isEmpty() ? null : target;
        });
        super.doOKAction();
    }

    private String getTargetText() {
        Object editorValue = targetCombo.getEditor().getItem();
        if (editorValue != null) {
            return editorValue.toString().trim();
        }
        Object selected = targetCombo.getSelectedItem();
        return selected != null ? selected.toString().trim() : "";
    }

    private void setTargetText(@Nullable String value) {
        if (value == null || value.isBlank()) {
            targetCombo.setSelectedItem("");
            return;
        }
        targetCombo.setSelectedItem(value);
        targetCombo.getEditor().setItem(value);
    }

    private static @Nullable String targetLabel(@NotNull FridaProcess p) {
        if (p.getIdentifier() != null && !p.getIdentifier().isBlank()) {
            return p.getIdentifier();
        }
        if (p.getName() != null && !p.getName().isBlank()) {
            return p.getName();
        }
        return null;
    }
}
