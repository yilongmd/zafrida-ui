package com.zafrida.ui.toolwindow;

import com.intellij.openapi.application.ApplicationInfo;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.diagnostic.Logger;
import com.intellij.openapi.progress.ProcessCanceledException;
import com.intellij.openapi.util.BuildNumber;
import com.intellij.openapi.util.JDOMUtil;
import com.intellij.util.io.HttpRequests;
import com.intellij.util.text.VersionComparatorUtil;
import com.zafrida.ui.util.ZaStrUtil;
import org.jdom.Element;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public final class ZaFridaPluginUpdateService {

    private static final Logger LOG = Logger.getInstance(ZaFridaPluginUpdateService.class);
    static final String PLUGIN_ID = "com.zafrida.ui";
    private static final String MARKETPLACE_DETAILS_URL =
            String.format("https://plugins.jetbrains.com/plugins/list?pluginId=%s", PLUGIN_ID);

    private final Object stateLock = new Object();
    private final List<Consumer<@Nullable String>> pendingCallbacks = new ArrayList<>();
    private boolean checkStarted;
    private boolean checkCompleted;
    private @Nullable String availableVersion;

    public void checkForUpdate(@NotNull String currentVersion,
                               @NotNull Consumer<@Nullable String> callback) {
        String completedVersion;
        boolean alreadyCompleted;
        boolean shouldStart = false;
        synchronized (stateLock) {
            alreadyCompleted = checkCompleted;
            if (alreadyCompleted) {
                completedVersion = availableVersion;
            } else {
                completedVersion = null;
                pendingCallbacks.add(callback);
                if (!checkStarted) {
                    checkStarted = true;
                    shouldStart = true;
                }
            }
        }

        if (alreadyCompleted) {
            ApplicationManager.getApplication().invokeLater(() -> callback.accept(completedVersion));
            return;
        }
        if (!shouldStart) {
            return;
        }
        ApplicationManager.getApplication().executeOnPooledThread(() -> runUpdateCheck(currentVersion));
    }

    private void runUpdateCheck(@NotNull String currentVersion) {
        String newerVersion = null;
        try {
            String response = HttpRequests.request(MARKETPLACE_DETAILS_URL)
                    .userAgent("ZAFrida-UI")
                    .connectTimeout(5_000)
                    .readTimeout(5_000)
                    .readString();
            BuildNumber currentBuild = ApplicationInfo.getInstance().getBuild();
            String latestCompatible = findLatestCompatibleVersion(response, currentBuild);
            if (ZaStrUtil.isNotBlank(latestCompatible)
                    && VersionComparatorUtil.compare(latestCompatible, currentVersion) > 0) {
                newerVersion = latestCompatible;
            }
        } catch (ProcessCanceledException e) {
            completeUpdateCheck(null);
            throw e;
        } catch (Exception e) {
            LOG.debug("ZAFrida Marketplace update check failed", e);
        }
        completeUpdateCheck(newerVersion);
    }

    private void completeUpdateCheck(@Nullable String newerVersion) {
        List<Consumer<@Nullable String>> callbacks;
        synchronized (stateLock) {
            availableVersion = newerVersion;
            checkCompleted = true;
            callbacks = new ArrayList<>(pendingCallbacks);
            pendingCallbacks.clear();
        }
        ApplicationManager.getApplication().invokeLater(() -> {
            for (Consumer<@Nullable String> callback : callbacks) {
                try {
                    callback.accept(newerVersion);
                } catch (RuntimeException e) {
                    LOG.warn("ZAFrida update callback failed", e);
                }
            }
        });
    }

    static @Nullable String findLatestCompatibleVersion(@NotNull String response,
                                                         @NotNull BuildNumber currentBuild) {
        if (ZaStrUtil.isBlank(response)) {
            return null;
        }
        try {
            Element rootElement = JDOMUtil.load(response);
            List<Element> pluginElements = new ArrayList<>();
            collectPluginElements(rootElement, pluginElements);
            String latestVersion = null;
            for (Element pluginElement : pluginElements) {
                if (!PLUGIN_ID.equals(pluginElement.getChildTextTrim("id"))) {
                    continue;
                }
                if (!isCompatibleWithBuild(pluginElement.getChild("idea-version"), currentBuild)) {
                    continue;
                }
                String version = pluginElement.getChildTextTrim("version");
                if (ZaStrUtil.isBlank(version)) {
                    continue;
                }
                if (latestVersion == null || VersionComparatorUtil.compare(version, latestVersion) > 0) {
                    latestVersion = version;
                }
            }
            return latestVersion;
        } catch (Exception e) {
            LOG.debug("Cannot parse ZAFrida Marketplace response", e);
            return null;
        }
    }

    private static void collectPluginElements(@NotNull Element element,
                                              @NotNull List<Element> pluginElements) {
        if ("idea-plugin".equals(element.getName())) {
            pluginElements.add(element);
        }
        for (Element child : element.getChildren()) {
            collectPluginElements(child, pluginElements);
        }
    }

    private static boolean isCompatibleWithBuild(@Nullable Element ideaVersion,
                                                 @NotNull BuildNumber currentBuild) {
        if (ideaVersion == null) {
            return true;
        }
        BuildNumber sinceBuild = parseBuildNumber(ideaVersion.getAttributeValue("since-build"));
        if (sinceBuild != null && currentBuild.compareTo(sinceBuild) < 0) {
            return false;
        }

        String untilText = ideaVersion.getAttributeValue("until-build");
        if (ZaStrUtil.isBlank(untilText)) {
            untilText = ideaVersion.getAttributeValue("max");
        }
        BuildNumber untilBuild = parseBuildNumber(untilText);
        return untilBuild == null || currentBuild.compareTo(untilBuild) <= 0;
    }

    private static @Nullable BuildNumber parseBuildNumber(@Nullable String value) {
        if (ZaStrUtil.isBlank(value) || "n/a".equalsIgnoreCase(value.trim())) {
            return null;
        }
        try {
            return BuildNumber.fromString(value.trim());
        } catch (RuntimeException e) {
            LOG.debug(String.format("Ignore invalid Marketplace build number: %s", value), e);
            return null;
        }
    }
}
