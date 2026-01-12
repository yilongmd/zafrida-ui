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

public final class SearchableComboBoxPanel<T> extends JPanel {

    private final JBTextField search = new JBTextField();
    private final ComboBox<T> combo = new ComboBox<>();
    private final DefaultComboBoxModel<T> model = new DefaultComboBoxModel<>();
    private final Function<T, String> text;

    private List<T> all = new ArrayList<>();

    public SearchableComboBoxPanel(@NotNull Function<T, String> textProvider) {
        super(new BorderLayout(0, 0));
        this.text = textProvider;

        search.getEmptyText().setText("Search...");
        combo.setModel(model);

        search.getDocument().addDocumentListener(new SimpleDocumentListener(this::refilter));

        add(search, BorderLayout.NORTH);
        add(combo, BorderLayout.CENTER);
    }

    public JBTextField getSearchField() { return search; }

    public void setItems(@NotNull List<T> items) {
        this.all = new ArrayList<>(items);
        refilter();
    }

    public @Nullable T getSelectedItem() { return (T) combo.getSelectedItem(); }

    public void setSelectedItem(@Nullable T v) { combo.setSelectedItem(v); }

    public void addActionListener(@NotNull java.awt.event.ActionListener l) { combo.addActionListener(l); }

    @Override public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        search.setEnabled(enabled);
        combo.setEnabled(enabled);
    }

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
