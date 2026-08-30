package com.zafrida.ui.toolwindow;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.project.DumbAware;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentFactory;
import com.zafrida.ui.config.ZaFridaGlobalSettings;
import com.zafrida.ui.ui.ZaFridaMainToolWindow;
import org.jetbrains.annotations.NotNull;

public final class ZaFridaToolWindowFactory implements ToolWindowFactory, DumbAware {

    @Override
    public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow toolWindow) {
        ZaFridaMainToolWindow mainPanel = new ZaFridaMainToolWindow(project);

        Content content = ContentFactory.getInstance().createContent(mainPanel, "", false);
        content.setDisposer(mainPanel);
        toolWindow.getContentManager().addContent(content);

        maybeShowEnvironmentDoctor(project, mainPanel);
    }

    private void maybeShowEnvironmentDoctor(@NotNull Project project, @NotNull ZaFridaMainToolWindow mainPanel) {
        ZaFridaGlobalSettings settings = ZaFridaGlobalSettings.getInstance();
        if (settings.environmentDoctorShown) {
            return;
        }
        settings.environmentDoctorShown = true;
        ApplicationManager.getApplication().invokeLater(() -> {
            if (project.isDisposed() || mainPanel.isDisposedForLifecycle()) {
                return;
            }
            mainPanel.getRunPanel().openEnvironmentDoctorDialog();
        });
    }
}
