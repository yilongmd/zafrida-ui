package com.zafrida.ui.ui;

import com.intellij.execution.impl.ConsoleViewImpl;
import com.intellij.execution.ui.ConsoleView;
import com.intellij.execution.ui.ConsoleViewContentType;
import com.intellij.execution.filters.TextConsoleBuilderFactory;
import com.intellij.icons.AllIcons;
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

/**
 * [UI组件] 自定义控制台面板。
 * <p>
 * 封装了 {@link ConsoleView}，并添加了简单的搜索工具栏。
 * 它是 {@link com.zafrida.ui.session.ZaFridaSessionService} 输出日志的目标容器。
 */
public final class ZaFridaConsolePanel extends JPanel implements Disposable {

    /** 控制台视图 */
    private final ConsoleView consoleView;
    /** 搜索输入框 */
    private final SearchTextField searchField = new SearchTextField();
    /** 上一次匹配起始位置 */
    private int lastMatchStart = -1;
    /** 上一次查询关键字 */
    private String lastQuery = "";

    /**
     * 构造函数。
     * @param project 当前 IDE 项目
     */
    public ZaFridaConsolePanel(Project project) {
        super(new BorderLayout());
        this.consoleView = TextConsoleBuilderFactory.getInstance()
                .createBuilder(project)
                .getConsole();
        add(buildSearchPanel(), BorderLayout.NORTH);
        add(consoleView.getComponent(), BorderLayout.CENTER);
    }

    /**
     * 获取控制台视图。
     * @return ConsoleView
     */
    public ConsoleView getConsoleView() {
        return consoleView;
    }

    /**
     * 清空控制台内容。
     */
    public void clear() {
        consoleView.clear();
        lastMatchStart = -1;
    }

    /**
     * 打印普通信息。
     * @param message 文本内容
     */
    public void info(String message) {
        consoleView.print(message + "\n", ConsoleViewContentType.NORMAL_OUTPUT);
    }

    /**
     * 打印警告信息。
     * @param message 文本内容
     */
    public void warn(String message) {
        consoleView.print(message + "\n", ConsoleViewContentType.LOG_WARNING_OUTPUT);
    }

    /**
     * 打印错误信息。
     * @param message 文本内容
     */
    public void error(String message) {
        consoleView.print(message + "\n", ConsoleViewContentType.ERROR_OUTPUT);
    }

    /**
     * 构建搜索工具栏。
     * @return 面板组件
     */
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

    /**
     * 查找下一个匹配项并定位光标。
     * @param forward true 表示向前查找
     */
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
        // 计算起始位置，优先从上一次匹配处继续
        int caretOffset = editor.getCaretModel().getOffset();
        int startIndex = resolveStartIndex(forward, caretOffset, text.length());
        int matchStart = forward
                ? findForward(text, query, startIndex)
                : findBackward(text, query, startIndex);
        if (matchStart == -1) {
            return;
        }
        // 选中并滚动到匹配位置
        int matchEnd = matchStart + query.length();
        lastMatchStart = matchStart;
        editor.getSelectionModel().setSelection(matchStart, matchEnd);
        editor.getCaretModel().moveToOffset(matchEnd);
        editor.getScrollingModel().scrollToCaret(ScrollType.MAKE_VISIBLE);
    }

    /**
     * 解析查找起始索引。
     * @param forward 是否向前
     * @param caretOffset 当前光标位置
     * @param textLength 文本长度
     * @return 起始索引
     */
    private int resolveStartIndex(boolean forward, int caretOffset, int textLength) {
        if (lastMatchStart != -1) {
            return forward ? lastMatchStart + 1 : lastMatchStart - 1;
        }
        if (forward) {
            return Math.min(caretOffset, textLength);
        }
        return Math.min(Math.max(caretOffset - 1, 0), Math.max(textLength - 1, 0));
    }

    /**
     * 向前查找匹配。
     * @param text 全文
     * @param query 查询关键字
     * @param startIndex 起始索引
     * @return 匹配起始位置或 -1
     */
    private int findForward(String text, String query, int startIndex) {
        int matchStart = text.indexOf(query, Math.max(startIndex, 0));
        if (matchStart == -1 && startIndex > 0) {
            matchStart = text.indexOf(query);
        }
        return matchStart;
    }

    /**
     * 向后查找匹配。
     * @param text 全文
     * @param query 查询关键字
     * @param startIndex 起始索引
     * @return 匹配起始位置或 -1
     */
    private int findBackward(String text, String query, int startIndex) {
        int safeIndex = Math.min(Math.max(startIndex, 0), Math.max(text.length() - 1, 0));
        int matchStart = text.lastIndexOf(query, safeIndex);
        if (matchStart == -1 && safeIndex < text.length() - 1) {
            matchStart = text.lastIndexOf(query);
        }
        return matchStart;
    }

    /**
     * 获取底层编辑器实例。
     * @return Editor 或 null
     */
    private Editor getEditor() {
        if (consoleView instanceof ConsoleViewImpl consoleViewImpl) {
            return consoleViewImpl.getEditor();
        }
        return null;
    }

    /**
     * 释放资源。
     */
    @Override
    public void dispose() {
        Disposer.dispose(consoleView);
    }
}
