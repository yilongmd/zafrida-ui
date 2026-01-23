package com.zafrida.ui.ui.components;

import com.intellij.openapi.ui.ComboBox;
import com.intellij.openapi.util.text.StringUtil;
import com.intellij.ui.components.JBTextField;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
/**
 * [UI组件] 带搜索过滤功能的下拉框面板。
 * <p>
 * <strong>结构：</strong>
 * 上方 {@link JBTextField} (搜索栏) + 下方 {@link ComboBox} (列表)。
 * <p>
 * <strong>用途：</strong>
 * 当列表项过多（如项目列表或进程列表）时，允许用户通过输入文本快速过滤 ComboBox 中的选项。
 */
public final class SearchableComboBoxPanel<T> extends JPanel {

    /** 搜索输入框 */
    private final JBTextField search = new JBTextField();
    /** 下拉框组件 */
    private final ComboBox<T> combo = new ComboBox<>();
    /** 下拉框数据模型 */
    private final DefaultComboBoxModel<T> model = new DefaultComboBoxModel<>();
    /** 文本展示函数 */
    private final Function<T, String> text;

    /** 全量数据列表 */
    private List<T> all = new ArrayList<>();

    /**
     * 构造函数。
     * @param textProvider 文本展示函数
     */
    public SearchableComboBoxPanel(@NotNull Function<T, String> textProvider) {
        super(new BorderLayout(0, 0));
        this.text = textProvider;

        search.getEmptyText().setText("Search...");
        combo.setModel(model);

        combo.setMinimumAndPreferredWidth(258);

        search.getDocument().addDocumentListener(new SimpleDocumentListener(this::refilter));

        add(search, BorderLayout.NORTH);
        add(combo, BorderLayout.CENTER);
    }

    /**
     * 获取搜索输入框。
     * @return 搜索输入框
     */
    public JBTextField getSearchField() {
        return search;
    }

    /**
     * 设置下拉框数据项。
     * @param items 数据项列表
     */
    public void setItems(@NotNull List<T> items) {
        this.all = new ArrayList<>(items);
        refilter();
    }

    /**
     * 获取当前选中项。
     * @return 选中项或 null
     */
    public @Nullable T getSelectedItem() {
        return (T) combo.getSelectedItem();
    }

    /**
     * 设置当前选中项。
     * @param v 选中项
     */
    public void setSelectedItem(@Nullable T v) {
        combo.setSelectedItem(v);
    }

    /**
     * 添加动作监听。
     * @param l 监听器
     */
    public void addActionListener(@NotNull java.awt.event.ActionListener l) {
        combo.addActionListener(l);
    }

    /**
     * 设置启用状态。
     * @param enabled 是否启用
     */
    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        search.setEnabled(enabled);
        combo.setEnabled(enabled);
    }

    /**
     * 按搜索关键字重新过滤数据。
     */
    private void refilter() {
        String q = StringUtil.toLowerCase(search.getText().trim());
        model.removeAllElements();
        for (T item : all) {
            String s = item == null ? "" : StringUtil.toLowerCase(text.apply(item));
            if (q.isEmpty() || s.contains(q)) model.addElement(item);
        }
        if (model.getSize() > 0 && combo.getSelectedItem() == null) combo.setSelectedIndex(0);
    }
}
