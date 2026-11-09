package com.zafrida.ui.toolwindow;

import com.intellij.ide.plugins.cl.PluginAwareClassLoader;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.options.ShowSettingsUtil;
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
        String pluginVersion = resolvePluginVersion();
        String toolWindowTitle = buildToolWindowTitle(pluginVersion);
        toolWindow.setTitle(toolWindowTitle);
        toolWindow.setStripeTitle(toolWindowTitle);
        ZaFridaMainToolWindow mainPanel = new ZaFridaMainToolWindow(project);

        Content content = ContentFactory.getInstance().createContent(mainPanel, "", false);
        content.setDisposer(mainPanel);
        toolWindow.getContentManager().addContent(content);

        configureUpdateIndicator(project, mainPanel, pluginVersion);
        maybeShowEnvironmentDoctor(project, mainPanel);
    }

    private void configureUpdateIndicator(@NotNull Project project,
                                          @NotNull ZaFridaMainToolWindow mainPanel,
                                          @NotNull String pluginVersion) {
        if (pluginVersion.isBlank()) {
            return;
        }
        ZaFridaPluginUpdateService updateService = ApplicationManager.getApplication()
                .getService(ZaFridaPluginUpdateService.class);
        updateService.checkForUpdate(pluginVersion, availableVersion -> {
            if (project.isDisposed() || mainPanel.isDisposedForLifecycle()) {
                return;
            }
            Runnable openPluginsAction = () -> ShowSettingsUtil.getInstance()
                    .showSettingsDialog(project, "Plugins");
            mainPanel.updatePluginUpdateIndicator(availableVersion, openPluginsAction);
        });
    }

    private @NotNull String resolvePluginVersion() {
        // PluginManagerCore.getPlugin 在新版平台属于 internal；自身类加载器可提供相同的版本信息。
        ClassLoader loader = getClass().getClassLoader();
        if (!(loader instanceof PluginAwareClassLoader)) {
            return "";
        }
        String version = ((PluginAwareClassLoader) loader).getPluginDescriptor().getVersion();
        if (version == null || version.isBlank()) {
            return "";
        }
        return version.trim();
    }

    private @NotNull String buildToolWindowTitle(@NotNull String pluginVersion) {
        if (pluginVersion.isBlank()) {
            return "ZAFrida";
        }
        return String.format("ZAFrida v%s", pluginVersion);
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
