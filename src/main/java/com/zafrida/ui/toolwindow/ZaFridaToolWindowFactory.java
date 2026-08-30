package com.zafrida.ui.toolwindow;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.ide.plugins.IdeaPluginDescriptor;
import com.intellij.ide.plugins.PluginManagerCore;
import com.intellij.openapi.extensions.PluginId;
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

    private static final String PLUGIN_ID = "com.zafrida.ui";

    @Override
    public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow toolWindow) {
        toolWindow.setTitle(resolveToolWindowTitle());
        ZaFridaMainToolWindow mainPanel = new ZaFridaMainToolWindow(project);

        Content content = ContentFactory.getInstance().createContent(mainPanel, "", false);
        content.setDisposer(mainPanel);
        toolWindow.getContentManager().addContent(content);

        maybeShowEnvironmentDoctor(project, mainPanel);
    }

    private @NotNull String resolveToolWindowTitle() {
        IdeaPluginDescriptor descriptor = PluginManagerCore.getPlugin(PluginId.getId(PLUGIN_ID));
        if (descriptor == null || descriptor.getVersion() == null || descriptor.getVersion().isBlank()) {
            return "ZAFrida";
        }
        return String.format("ZAFrida v%s", descriptor.getVersion());
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
