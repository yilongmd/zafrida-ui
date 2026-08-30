package com.zafrida.ui.ui;

import com.intellij.execution.impl.ConsoleViewImpl;
import com.intellij.execution.ui.ConsoleView;
import com.intellij.execution.ui.ConsoleViewContentType;
import com.intellij.execution.filters.TextConsoleBuilderFactory;
import com.intellij.icons.AllIcons;
import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.fileEditor.FileEditorManager;
import com.intellij.openapi.util.Disposer;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.editor.ScrollType;
import com.intellij.openapi.util.TextRange;
import com.intellij.openapi.vfs.LocalFileSystem;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.ui.SearchTextField;
import com.zafrida.ui.util.ProjectFileUtil;
import com.zafrida.ui.util.ZaFridaIcons;
import com.zafrida.ui.util.ZaFridaNotifier;
import com.zafrida.ui.util.ZaFridaVsCodeUtil;
import com.zafrida.ui.util.ZaStrUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.io.File;

public final class ZaFridaConsolePanel extends JPanel implements Disposable {

    private final @NotNull Project project;

    private final JLabel logFileLabel = new JLabel("Log: (not started)");
    private final JButton locateLogFileBtn = new JButton("");
    private final JButton openLogFileBtn = new JButton("");
    private final JButton openLogFileInVsCodeBtn = new JButton("");
    private final JButton clearConsoleBtn = new JButton("");
    private @Nullable String lastLogFilePath;

    private final ConsoleView consoleView;
    private final SearchTextField searchField = new SearchTextField();
    private int lastMatchStart = -1;
    private String lastQuery = "";

    public ZaFridaConsolePanel(@NotNull Project project) {
        super(new BorderLayout());
        this.project = project;
        this.consoleView = TextConsoleBuilderFactory.getInstance()
                .createBuilder(project)
                .getConsole();
        initLogToolbar();
        add(buildTopToolbarPanel(), BorderLayout.NORTH);
        add(consoleView.getComponent(), BorderLayout.CENTER);
    }

    public ConsoleView getConsoleView() {
        return consoleView;
    }

    public void clear() {
        consoleView.clear();
        lastMatchStart = -1;
    }

    public void info(String message) {
        consoleView.print(String.format("%s\n", message), ConsoleViewContentType.NORMAL_OUTPUT);
    }

    public void warn(String message) {
        consoleView.print(String.format("%s\n", message), ConsoleViewContentType.LOG_WARNING_OUTPUT);
    }

    public void error(String message) {
        consoleView.print(String.format("%s\n", message), ConsoleViewContentType.ERROR_OUTPUT);
    }

    public void setLogFilePath(@Nullable String logFilePath) {
        this.lastLogFilePath = logFilePath;

        if (ZaStrUtil.isBlank(logFilePath)) {
            logFileLabel.setText("Log: (not started)");
            logFileLabel.setToolTipText("Log: (not started)");
            locateLogFileBtn.setEnabled(false);
            openLogFileBtn.setEnabled(false);
            openLogFileInVsCodeBtn.setEnabled(false);
            return;
        }

        String trimmed = logFilePath.trim();
        logFileLabel.setText(String.format("Log: %s", trimmed));
        logFileLabel.setToolTipText(trimmed);

        boolean enabled = !trimmed.startsWith("(");
        locateLogFileBtn.setEnabled(enabled);
        openLogFileBtn.setEnabled(enabled);
        openLogFileInVsCodeBtn.setEnabled(enabled);
    }

    public @Nullable String getLogFilePath() {
        return lastLogFilePath;
    }

    public int getConsoleTextLength() {
        Editor editor = getEditor();
        if (editor == null) {
            return 0;
        }
        return editor.getDocument().getTextLength();
    }

    public @NotNull String getConsoleTextTailSnapshot(int maxCharacters) {
        Editor editor = getEditor();
        if (editor == null || maxCharacters <= 0) {
            return "";
        }
        Document document = editor.getDocument();
        int end = document.getTextLength();
        int start = Math.max(0, end - maxCharacters);
        return document.getText(new TextRange(start, end));
    }

    private void initLogToolbar() {
        locateLogFileBtn.setIcon(AllIcons.General.Locate);
        locateLogFileBtn.setToolTipText("Locate log file in Project View");
        tuneLogToolbarIconButton(locateLogFileBtn);
        locateLogFileBtn.setEnabled(false);

        openLogFileBtn.setIcon(AllIcons.Actions.EditSource);
        openLogFileBtn.setToolTipText("Open log file in editor");
        tuneLogToolbarIconButton(openLogFileBtn);
        openLogFileBtn.setEnabled(false);

        openLogFileInVsCodeBtn.setIcon(ZaFridaIcons.VSCODE);
        openLogFileInVsCodeBtn.setToolTipText("Open log file in VS Code");
        tuneLogToolbarIconButton(openLogFileInVsCodeBtn);
        openLogFileInVsCodeBtn.setEnabled(false);

        clearConsoleBtn.setIcon(AllIcons.Actions.ClearCash);
        clearConsoleBtn.setToolTipText("Clear console (does not affect log file)");
        tuneLogToolbarIconButton(clearConsoleBtn);

        locateLogFileBtn.addActionListener(e -> locateLogFileInProjectView());
        openLogFileBtn.addActionListener(e -> openLogFileInEditor());
        openLogFileInVsCodeBtn.addActionListener(e -> openLogFileInVsCode());
        clearConsoleBtn.addActionListener(e -> clear());
    }

    private JPanel buildTopToolbarPanel() {
        JPanel top = new JPanel(new BorderLayout(0, 4));
        top.add(buildLogToolbarPanel(), BorderLayout.NORTH);
        top.add(buildSearchPanel(), BorderLayout.SOUTH);
        return top;
    }

    private JPanel buildLogToolbarPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 0));
        panel.add(logFileLabel, BorderLayout.CENTER);

        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        actionsPanel.add(clearConsoleBtn);
        actionsPanel.add(locateLogFileBtn);
        actionsPanel.add(openLogFileBtn);
        actionsPanel.add(openLogFileInVsCodeBtn);
        panel.add(actionsPanel, BorderLayout.EAST);
        return panel;
    }

    private JPanel buildSearchPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 0));
        searchField.getTextEditor().addActionListener(event -> findNext(true));
        panel.add(searchField, BorderLayout.CENTER);

        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        JButton prevButton = new JButton(AllIcons.Actions.PreviousOccurence);
        JButton nextButton = new JButton(AllIcons.Actions.NextOccurence);
        prevButton.setToolTipText("Previous Occurrence");
        nextButton.setToolTipText("Next Occurrence");
        prevButton.addActionListener(event -> findNext(false));
        nextButton.addActionListener(event -> findNext(true));
        actionsPanel.add(prevButton);
        actionsPanel.add(nextButton);
        panel.add(actionsPanel, BorderLayout.EAST);
        return panel;
    }

    private void locateLogFileInProjectView() {
        String rawPath = lastLogFilePath;
        String path = normalizeLogFilePath(rawPath);
        if (path == null) {
            notifyLogFileUnavailable(rawPath);
            return;
        }

        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            VirtualFile file = LocalFileSystem.getInstance().refreshAndFindFileByPath(path);
            if (file != null && file.isValid() && !file.isDirectory()) {
                ApplicationManager.getApplication().invokeLater(() -> ProjectFileUtil.openAndSelectLogFileReadOnly(project, file));
                return;
            }

            File ioFile = new File(path);
            File parent = ioFile.getParentFile();
            if (parent != null) {
                VirtualFile dir = LocalFileSystem.getInstance().refreshAndFindFileByIoFile(parent);
                if (dir != null && dir.isValid()) {
                    ApplicationManager.getApplication().invokeLater(() -> {
                        ProjectFileUtil.openAndSelectInProject(project, dir);
                        ZaFridaNotifier.warn(project, "ZAFrida", String.format("Log file not found, located directory: %s", parent.getAbsolutePath()));
                    });
                    return;
                }
            }

            ApplicationManager.getApplication().invokeLater(() ->
                    ZaFridaNotifier.warn(project, "ZAFrida", String.format("Log file not found: %s", path)));
        });
    }

    private void openLogFileInEditor() {
        String rawPath = lastLogFilePath;
        String path = normalizeLogFilePath(rawPath);
        if (path == null) {
            notifyLogFileUnavailable(rawPath);
            return;
        }

        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            VirtualFile file = LocalFileSystem.getInstance().refreshAndFindFileByPath(path);
            if (file == null || !file.isValid() || file.isDirectory()) {
                ApplicationManager.getApplication().invokeLater(() ->
                        ZaFridaNotifier.warn(project, "ZAFrida", String.format("Log file not found: %s", path)));
                return;
            }
            ApplicationManager.getApplication().invokeLater(() ->
                    FileEditorManager.getInstance(project).openFile(file, true));
        });
    }

    private void openLogFileInVsCode() {
        String rawPath = lastLogFilePath;
        String path = normalizeLogFilePath(rawPath);
        if (path == null) {
            notifyLogFileUnavailable(rawPath);
            return;
        }
        ZaFridaVsCodeUtil.openFileInVsCodeAsync(project, path);
    }

    private static void tuneLogToolbarIconButton(@NotNull JButton btn) {
        btn.setBorderPainted(false);
        btn.setContentAreaFilled(false);
        btn.setFocusPainted(false);
        btn.setOpaque(false);
        btn.setMargin(new Insets(0, 0, 0, 0));
        btn.setPreferredSize(new Dimension(18, 18));
    }

    private static @Nullable String normalizeLogFilePath(@Nullable String rawPath) {
        if (ZaStrUtil.isBlank(rawPath)) {
            return null;
        }
        String trimmed = rawPath.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        if (trimmed.startsWith("(")) {
            return null;
        }
        return trimmed;
    }

    private void notifyLogFileUnavailable(@Nullable String rawPath) {
        if (ZaStrUtil.isBlank(rawPath)) {
            ZaFridaNotifier.warn(project, "ZAFrida", "No log file yet");
            return;
        }
        String trimmed = rawPath.trim();
        if (trimmed.startsWith("(")) {
            ZaFridaNotifier.warn(project, "ZAFrida", String.format("Log file not available: %s", trimmed));
            return;
        }
        ZaFridaNotifier.warn(project, "ZAFrida", String.format("Log file not found: %s", trimmed));
    }

    private void findNext(boolean forward) {
        String query = searchField.getText();
        if (ZaStrUtil.isBlank(query)) {
            return;
        }
        Editor editor = getEditor();
        if (editor == null) {
            return;
        }
        Document document = editor.getDocument();
        String text = document.getText();
        if (!query.equals(lastQuery)) {
            lastQuery = query;
            lastMatchStart = -1;
        }
        if (text.isEmpty()) {
            return;
        }
        int caretOffset = editor.getCaretModel().getOffset();
        int startIndex = resolveStartIndex(forward, caretOffset, text.length());
        int matchStart = forward
                ? findForward(text, query, startIndex)
                : findBackward(text, query, startIndex);
        if (matchStart == -1) {
            return;
        }
        int matchEnd = matchStart + query.length();
        lastMatchStart = matchStart;
        editor.getSelectionModel().setSelection(matchStart, matchEnd);
        editor.getCaretModel().moveToOffset(matchEnd);
        editor.getScrollingModel().scrollToCaret(ScrollType.MAKE_VISIBLE);
    }

    private int resolveStartIndex(boolean forward, int caretOffset, int textLength) {
        if (lastMatchStart != -1) {
            if (forward) {
                return lastMatchStart + 1;
            }
            return lastMatchStart - 1;
        }
        if (forward) {
            return Math.min(caretOffset, textLength);
        }
        return Math.min(Math.max(caretOffset - 1, 0), Math.max(textLength - 1, 0));
    }

    private int findForward(String text, String query, int startIndex) {
        int matchStart = text.indexOf(query, Math.max(startIndex, 0));
        if (matchStart == -1 && startIndex > 0) {
            matchStart = text.indexOf(query);
        }
        return matchStart;
    }

    private int findBackward(String text, String query, int startIndex) {
        int safeIndex = Math.min(Math.max(startIndex, 0), Math.max(text.length() - 1, 0));
        int matchStart = text.lastIndexOf(query, safeIndex);
        if (matchStart == -1 && safeIndex < text.length() - 1) {
            matchStart = text.lastIndexOf(query);
        }
        return matchStart;
    }

    private Editor getEditor() {
        if (consoleView instanceof ConsoleViewImpl consoleViewImpl) {
            return consoleViewImpl.getEditor();
        }
        return null;
    }

    @Override
    public void dispose() {
        Disposer.dispose(consoleView);
    }
}
