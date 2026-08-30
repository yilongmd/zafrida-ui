package com.zafrida.ui.fridaproject.ui;

import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.application.ModalityState;
import com.intellij.openapi.project.Project;
import com.intellij.ui.JBColor;
import com.zafrida.ui.frida.FridaCliService;
import com.zafrida.ui.python.ProjectPythonEnvResolver;
import com.zafrida.ui.python.PythonEnvInfo;
import com.zafrida.ui.util.ZaFridaIcons;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JLabel;
import java.awt.Color;
import java.util.function.Consumer;

final class ZaFridaEnvironmentDetailsController {

    private final Project project;
    private final FridaCliService fridaCliService;
    private final JLabel sourceLabel = new JLabel("Not resolved");
    private final JLabel resolvedPythonLabel = new JLabel("Not resolved");
    private final JLabel fridaVersionLabel = new JLabel("Not detected");
    private final Color defaultLabelForeground;
    private int inspectionGeneration;

    ZaFridaEnvironmentDetailsController(@NotNull Project project,
                                        @NotNull FridaCliService fridaCliService) {
        this.project = project;
        this.fridaCliService = fridaCliService;
        fridaVersionLabel.setIcon(ZaFridaIcons.FRIDA_PROJECT);
        fridaVersionLabel.setIconTextGap(6);
        defaultLabelForeground = fridaVersionLabel.getForeground();
    }

    @NotNull JLabel getSourceLabel() {
        return sourceLabel;
    }

    @NotNull JLabel getResolvedPythonLabel() {
        return resolvedPythonLabel;
    }

    @NotNull JLabel getFridaVersionLabel() {
        return fridaVersionLabel;
    }

    void inspect(@NotNull String configuredPath,
                 @NotNull ModalityState modality,
                 @NotNull Consumer<InspectionResult> completion) {
        int generation = ++inspectionGeneration;
        setLoading();
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            InspectionResult result = inspectInBackground(configuredPath);
            ApplicationManager.getApplication().invokeLater(() -> {
                if (generation != inspectionGeneration || project.isDisposed()) {
                    return;
                }
                apply(result);
                completion.accept(result);
            }, modality);
        });
    }

    void markStale() {
        inspectionGeneration++;
        sourceLabel.setText("Pending validation");
        resolvedPythonLabel.setText("Click Test to resolve");
        resolvedPythonLabel.setToolTipText(null);
        fridaVersionLabel.setText("Click Test");
        fridaVersionLabel.setForeground(defaultLabelForeground);
        fridaVersionLabel.setToolTipText("Test the selected Python environment to detect Frida");
    }

    void setUnavailable(@Nullable String reason) {
        inspectionGeneration++;
        sourceLabel.setText("Unavailable");
        resolvedPythonLabel.setText("Not resolved");
        resolvedPythonLabel.setToolTipText(reason);
        setFridaUnavailable(reason);
    }

    void cancelPendingInspection() {
        inspectionGeneration++;
    }

    private void setLoading() {
        sourceLabel.setText("Resolving…");
        resolvedPythonLabel.setText("Resolving…");
        resolvedPythonLabel.setToolTipText(null);
        fridaVersionLabel.setText("Detecting…");
        fridaVersionLabel.setForeground(defaultLabelForeground);
        fridaVersionLabel.setToolTipText("Detecting Frida version");
    }

    private @NotNull InspectionResult inspectInBackground(@NotNull String configuredPath) {
        PythonEnvInfo environment;
        try {
            if (configuredPath.isEmpty()) {
                environment = ProjectPythonEnvResolver.resolveIdeProject(project);
            } else {
                environment = ProjectPythonEnvResolver.resolveConfiguredPath(configuredPath);
            }
            if (environment == null) {
                return InspectionResult.failure(null, "PyCharm project Python interpreter was not found");
            }
        } catch (RuntimeException e) {
            return InspectionResult.failure(null, errorMessage(e));
        }

        try {
            String version = fridaCliService.detectFridaPythonVersion(environment);
            return InspectionResult.success(environment, version);
        } catch (RuntimeException e) {
            return InspectionResult.failure(environment, errorMessage(e));
        }
    }

    private void apply(@NotNull InspectionResult result) {
        PythonEnvInfo environment = result.getEnvironment();
        if (environment == null) {
            sourceLabel.setText("Unavailable");
            resolvedPythonLabel.setText("Not resolved");
            resolvedPythonLabel.setToolTipText(result.getErrorMessage());
            setFridaUnavailable(result.getErrorMessage());
            return;
        }

        sourceLabel.setText(environmentSourceText(environment));
        resolvedPythonLabel.setText(environment.getPythonHome());
        resolvedPythonLabel.setToolTipText(String.format("Environment root: %s", environment.getEnvRoot()));
        if (ZaStrUtil.isBlank(result.getFridaVersion())) {
            setFridaUnavailable(result.getErrorMessage());
            return;
        }
        fridaVersionLabel.setText(result.getFridaVersion());
        fridaVersionLabel.setForeground(defaultLabelForeground);
        fridaVersionLabel.setToolTipText(String.format(
                "Frida %s in %s",
                result.getFridaVersion(),
                environment.getEnvRoot()
        ));
    }

    private void setFridaUnavailable(@Nullable String reason) {
        fridaVersionLabel.setText("Unavailable");
        fridaVersionLabel.setForeground(JBColor.RED);
        fridaVersionLabel.setToolTipText(reason);
    }

    static @NotNull String environmentSourceText(@NotNull PythonEnvInfo environment) {
        if (environment.getSource() == PythonEnvInfo.Source.ZAFRIDA_PROJECT) {
            return "ZAFrida project override";
        }
        return "PyCharm project interpreter";
    }

    private static @NotNull String errorMessage(@NotNull RuntimeException error) {
        String message = error.getMessage();
        if (ZaStrUtil.isBlank(message)) {
            return error.getClass().getSimpleName();
        }
        return message;
    }

    static final class InspectionResult {
        private final @Nullable PythonEnvInfo environment;
        private final @Nullable String fridaVersion;
        private final @Nullable String errorMessage;

        private InspectionResult(@Nullable PythonEnvInfo environment,
                                 @Nullable String fridaVersion,
                                 @Nullable String errorMessage) {
            this.environment = environment;
            this.fridaVersion = fridaVersion;
            this.errorMessage = errorMessage;
        }

        static @NotNull InspectionResult success(@NotNull PythonEnvInfo environment,
                                                  @NotNull String fridaVersion) {
            return new InspectionResult(environment, fridaVersion, null);
        }

        static @NotNull InspectionResult failure(@Nullable PythonEnvInfo environment,
                                                  @NotNull String errorMessage) {
            return new InspectionResult(environment, null, errorMessage);
        }

        @Nullable PythonEnvInfo getEnvironment() {
            return environment;
        }

        @Nullable String getFridaVersion() {
            return fridaVersion;
        }

        @Nullable String getErrorMessage() {
            return errorMessage;
        }
    }
}
