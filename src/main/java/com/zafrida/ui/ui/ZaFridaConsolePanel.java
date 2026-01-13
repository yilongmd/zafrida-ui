package com.zafrida.ui.ui;

import com.intellij.execution.impl.ConsoleViewImpl;
import com.intellij.execution.ui.ConsoleView;
import com.intellij.execution.ui.ConsoleViewContentType;
import com.intellij.execution.filters.TextConsoleBuilderFactory;
import com.intellij.openapi.Disposable;
import com.intellij.openapi.util.Disposer;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.editor.Document;
import com.intellij.openapi.editor.Editor;
import com.intellij.openapi.editor.ScrollType;
import com.intellij.ui.SearchTextField;

import javax.swing.JButton;
import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.FlowLayout;

public final class ZaFridaConsolePanel extends JPanel implements Disposable {

    private final ConsoleView consoleView;
    private final SearchTextField searchField = new SearchTextField();
    private int lastMatchStart = -1;
    private String lastQuery = "";

    public ZaFridaConsolePanel(Project project) {
        super(new BorderLayout());
        this.consoleView = TextConsoleBuilderFactory.getInstance()
                .createBuilder(project)
                .getConsole();
        add(buildSearchPanel(), BorderLayout.NORTH);
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
        consoleView.print(message + "\n", ConsoleViewContentType.NORMAL_OUTPUT);
    }

    public void warn(String message) {
        consoleView.print(message + "\n", ConsoleViewContentType.LOG_WARNING_OUTPUT);
    }

    public void error(String message) {
        consoleView.print(message + "\n", ConsoleViewContentType.ERROR_OUTPUT);
    }

    private JPanel buildSearchPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 0));
        searchField.addActionListener(event -> findNext(true));
        panel.add(searchField, BorderLayout.CENTER);

        JPanel actionsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        JButton prevButton = new JButton("Prev");
        JButton nextButton = new JButton("Next");
        prevButton.addActionListener(event -> findNext(false));
        nextButton.addActionListener(event -> findNext(true));
        actionsPanel.add(prevButton);
        actionsPanel.add(nextButton);
        panel.add(actionsPanel, BorderLayout.EAST);
        return panel;
    }

    private void findNext(boolean forward) {
        String query = searchField.getText();
        if (query.isBlank()) {
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
            return forward ? lastMatchStart + 1 : lastMatchStart - 1;
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
