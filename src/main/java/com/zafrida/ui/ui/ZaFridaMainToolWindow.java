package com.zafrida.ui.ui;

import com.intellij.ide.util.PropertiesComponent;
import com.intellij.openapi.Disposable;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.Splitter;
import com.intellij.openapi.util.Disposer;
import com.intellij.ui.OnePixelSplitter;
import com.intellij.ui.components.ActionLink;
import com.intellij.ui.components.JBTabbedPane;
import com.intellij.icons.AllIcons;
import com.zafrida.ui.util.ZaFridaIcons;
import com.intellij.util.ui.JBUI;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;

public final class ZaFridaMainToolWindow extends JPanel implements Disposable {

    private static final String MAIN_SPLITTER_PROPORTION_KEY = "zafrida.main.console.splitter.proportion";
    private static final float FALLBACK_SPLITTER_PROPORTION = 0.5F;
    private static final int MINIMUM_TOOL_WINDOW_WIDTH = 360;
    private static final int PREFERRED_TOOL_WINDOW_WIDTH = 440;
    private static final int MINIMUM_CONSOLE_HEIGHT = 180;

    private final JBTabbedPane tabbedPane;
    private final ZaFridaRunPanel runPanel;
    private final ZaFridaTemplatePanel templatePanel;
    private final ZaFridaToolsPanel toolsPanel;
    private final ZaFridaConsoleTabsPanel consoleTabsPanel;
    private final JPanel pluginUpdateRow = new JPanel(new BorderLayout());
    private final ActionLink pluginUpdateLink = new ActionLink("");
    private @Nullable Runnable pluginUpdateAction;
    private volatile boolean disposed;

    public ZaFridaMainToolWindow(@NotNull Project project) {
        super(new BorderLayout());
        setMinimumSize(new Dimension(JBUI.scale(MINIMUM_TOOL_WINDOW_WIDTH), 0));
        setPreferredSize(new Dimension(JBUI.scale(PREFERRED_TOOL_WINDOW_WIDTH), JBUI.scale(760)));

        this.consoleTabsPanel = new ZaFridaConsoleTabsPanel(project);
        this.templatePanel = new ZaFridaTemplatePanel(project, consoleTabsPanel.getRunConsolePanel());
        this.runPanel = new ZaFridaRunPanel(project, consoleTabsPanel, templatePanel);
        this.toolsPanel = new ZaFridaToolsPanel(project, consoleTabsPanel);

        Disposer.register(this, consoleTabsPanel);
        Disposer.register(this, templatePanel);
        Disposer.register(this, runPanel);
        Disposer.register(this, toolsPanel);

        tabbedPane = new JBTabbedPane();
        tabbedPane.setTabComponentInsets(JBUI.emptyInsets());

        tabbedPane.addTab("Session", runPanel);
        tabbedPane.addTab("Templates", templatePanel);
        tabbedPane.addTab("Tools", toolsPanel);

        JPanel header = buildHeader();
        JPanel topContainer = new JPanel(new BorderLayout());
        topContainer.add(header, BorderLayout.NORTH);
        topContainer.add(tabbedPane, BorderLayout.CENTER);

        consoleTabsPanel.setMinimumSize(new Dimension(0, JBUI.scale(MINIMUM_CONSOLE_HEIGHT)));
        OnePixelSplitter splitPane = new OnePixelSplitter(true, FALLBACK_SPLITTER_PROPORTION);
        splitPane.setFirstComponent(topContainer);
        splitPane.setSecondComponent(consoleTabsPanel);
        splitPane.setDividerWidth(JBUI.scale(4));
        splitPane.setHonorComponentsMinimumSize(true);
        splitPane.setDividerPositionStrategy(Splitter.DividerPositionStrategy.KEEP_FIRST_SIZE);
        splitPane.setBorder(JBUI.Borders.empty());
        configureInitialSplitterPosition(splitPane, topContainer);

        add(splitPane, BorderLayout.CENTER);
    }

    public @NotNull ZaFridaConsoleTabsPanel getConsoleTabsPanel() {
        return consoleTabsPanel;
    }

    public @NotNull ZaFridaRunPanel getRunPanel() {
        return runPanel;
    }

    public @NotNull ZaFridaTemplatePanel getTemplatePanel() {
        return templatePanel;
    }

    public boolean isDisposedForLifecycle() {
        return disposed;
    }

    public void updatePluginUpdateIndicator(@Nullable String availableVersion,
                                            @Nullable Runnable updateAction) {
        if (availableVersion == null || availableVersion.isBlank()) {
            pluginUpdateAction = null;
            pluginUpdateLink.setText("");
            pluginUpdateLink.setToolTipText(null);
            pluginUpdateRow.setVisible(false);
            revalidate();
            repaint();
            return;
        }
        pluginUpdateAction = updateAction;
        pluginUpdateLink.setText(String.format("Update available · v%s", availableVersion));
        pluginUpdateLink.setToolTipText(String.format(
                "ZAFrida v%s is available; open Plugins settings",
                availableVersion
        ));
        pluginUpdateRow.setVisible(true);
        revalidate();
        repaint();
    }

    private void configureInitialSplitterPosition(@NotNull OnePixelSplitter splitPane,
                                                  @NotNull JPanel topContainer) {
        PropertiesComponent properties = PropertiesComponent.getInstance();
        if (properties.isValueSet(MAIN_SPLITTER_PROPORTION_KEY)) {
            splitPane.setAndLoadSplitterProportionKey(MAIN_SPLITTER_PROPORTION_KEY);
            return;
        }

        splitPane.addComponentListener(new ComponentAdapter() {
            private boolean initialized;

            @Override
            public void componentResized(ComponentEvent event) {
                if (initialized) {
                    return;
                }
                int availableHeight = splitPane.getHeight() - splitPane.getDividerWidth();
                if (availableHeight <= 0) {
                    return;
                }
                initialized = true;

                int firstComponentHeight = topContainer.getPreferredSize().height;
                int maximumFirstComponentHeight = availableHeight - JBUI.scale(MINIMUM_CONSOLE_HEIGHT);
                if (firstComponentHeight > maximumFirstComponentHeight) {
                    firstComponentHeight = maximumFirstComponentHeight;
                }
                if (firstComponentHeight < 0) {
                    firstComponentHeight = 0;
                }

                float proportion = (float) firstComponentHeight / availableHeight;
                if (proportion < splitPane.getMinimumProportion()) {
                    proportion = splitPane.getMinimumProportion();
                }
                if (proportion > splitPane.getMaximumProportion()) {
                    proportion = splitPane.getMaximumProportion();
                }
                splitPane.setProportion(proportion);
                splitPane.setSplitterProportionKey(MAIN_SPLITTER_PROPORTION_KEY);
                splitPane.removeComponentListener(this);
            }
        });
    }

    private JPanel buildHeader() {
        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setBorder(JBUI.Borders.empty(6, 8));

        JPanel projectRow = new JPanel(new GridLayout(1, 4, JBUI.scale(6), 0));
        JButton newProjectBtn = new JButton("New Project");
        newProjectBtn.setIcon(scaleIcon(ZaFridaIcons.FRIDA_PROJECT, 0.875F));
        newProjectBtn.setToolTipText("New Frida Project");
        newProjectBtn.addActionListener(e -> runPanel.openNewProjectDialog());

        JButton projectSettingsBtn = new JButton("Project");
        projectSettingsBtn.setIcon(AllIcons.General.Settings);
        projectSettingsBtn.setToolTipText("Open project settings");
        projectSettingsBtn.addActionListener(e -> runPanel.openProjectSettingsDialog());

        JButton globalSettingsBtn = new JButton("Global");
        globalSettingsBtn.setIcon(AllIcons.General.Settings);
        globalSettingsBtn.setToolTipText("Open global settings");
        globalSettingsBtn.addActionListener(e -> runPanel.openGlobalSettingsDialog());

        JButton doctorBtn = new JButton("Doctor");
        doctorBtn.setIcon(AllIcons.General.InspectionsOK);
        doctorBtn.setToolTipText("Environment doctor");
        doctorBtn.addActionListener(e -> runPanel.openEnvironmentDoctorDialog());

        tuneHeaderButton(newProjectBtn);
        tuneHeaderButton(projectSettingsBtn);
        tuneHeaderButton(globalSettingsBtn);
        tuneHeaderButton(doctorBtn);

        projectRow.add(newProjectBtn);
        projectRow.add(projectSettingsBtn);
        projectRow.add(globalSettingsBtn);
        projectRow.add(doctorBtn);

        pluginUpdateLink.setIcon(AllIcons.General.Warning);
        pluginUpdateLink.setIconTextGap(JBUI.scale(4));
        pluginUpdateLink.setFont(pluginUpdateLink.getFont().deriveFont(Font.BOLD));
        pluginUpdateLink.addActionListener(event -> {
            Runnable action = pluginUpdateAction;
            if (action != null) {
                action.run();
            }
        });
        pluginUpdateRow.setBorder(JBUI.Borders.emptyTop(2));
        pluginUpdateRow.add(pluginUpdateLink, BorderLayout.EAST);
        pluginUpdateRow.setVisible(false);

        header.add(projectRow);
        header.add(pluginUpdateRow);

        return header;
    }

    private static void tuneHeaderButton(@NotNull JButton button) {
        button.setMargin(JBUI.insets(2, 2));
        button.setIconTextGap(JBUI.scale(2));
    }

    private static @NotNull Icon scaleIcon(@NotNull Icon baseIcon, float scale) {
        float effectiveScale = scale;
        if (effectiveScale <= 0.0F) {
            effectiveScale = 1.0F;
        }
        final float finalScale = effectiveScale;
        return new Icon() {
            @Override
            public void paintIcon(Component c, Graphics g, int x, int y) {
                Graphics2D g2 = (Graphics2D) g.create();
                try {
                    g2.translate(x, y);
                    g2.scale(finalScale, finalScale);
                    baseIcon.paintIcon(c, g2, 0, 0);
                } finally {
                    g2.dispose();
                }
            }

            @Override
            public int getIconWidth() {
                return Math.max(1, Math.round(baseIcon.getIconWidth() * finalScale));
            }

            @Override
            public int getIconHeight() {
                return Math.max(1, Math.round(baseIcon.getIconHeight() * finalScale));
            }
        };
    }

    @Override
    public void dispose() {
        disposed = true;
        // 子组件已注册到 Disposer，无需重复释放。
    }
}
