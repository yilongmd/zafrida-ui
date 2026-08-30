package com.zafrida.ui.ui.components;

import com.intellij.icons.AllIcons;
import com.intellij.openapi.ui.ComboBox;
import com.intellij.openapi.util.text.StringUtil;
import com.intellij.ui.components.JBTextField;
import com.intellij.util.ui.JBUI;
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
    private final JButton searchToggleButton = new JButton();
    private final DefaultComboBoxModel<T> model = new DefaultComboBoxModel<>();
    private final Function<T, String> text;

    private List<T> all = new ArrayList<>();
    private boolean updatingModel;

    public SearchableComboBoxPanel(@NotNull Function<T, String> textProvider) {
        super(new BorderLayout(0, 0));
        this.text = textProvider;

        search.getEmptyText().setText("Search...");
        combo.setModel(model);

        Dimension comboMinimumSize = combo.getMinimumSize();
        combo.setMinimumSize(new Dimension(JBUI.scale(120), comboMinimumSize.height));

        search.getDocument().addDocumentListener(new SimpleDocumentListener(this::refilter));
        search.setVisible(false);

        searchToggleButton.setIcon(AllIcons.Actions.Search);
        searchToggleButton.setToolTipText("Search projects");
        searchToggleButton.setMargin(JBUI.emptyInsets());
        searchToggleButton.getAccessibleContext().setAccessibleName("Search projects");
        searchToggleButton.addActionListener(event -> setSearchVisible(!search.isVisible()));

        add(search, BorderLayout.NORTH);

        JPanel selectorRow = new JPanel(new BorderLayout(JBUI.scale(4), 0));
        selectorRow.add(combo, BorderLayout.CENTER);
        selectorRow.add(searchToggleButton, BorderLayout.EAST);
        add(selectorRow, BorderLayout.CENTER);
    }

    public JBTextField getSearchField() {
        return search;
    }

    public boolean isSearchVisible() {
        return search.isVisible();
    }

    public void setSearchVisible(boolean visible) {
        if (search.isVisible() == visible) {
            return;
        }
        if (visible) {
            search.setVisible(true);
            searchToggleButton.setIcon(AllIcons.Actions.Close);
            searchToggleButton.setToolTipText("Close project search");
            searchToggleButton.getAccessibleContext().setAccessibleName("Close project search");
            SwingUtilities.invokeLater(search::requestFocusInWindow);
        } else {
            T selectedItem = getSelectedItem();
            search.setText("");
            if (selectedItem != null) {
                combo.setSelectedItem(selectedItem);
            }
            search.setVisible(false);
            searchToggleButton.setIcon(AllIcons.Actions.Search);
            searchToggleButton.setToolTipText("Search projects");
            searchToggleButton.getAccessibleContext().setAccessibleName("Search projects");
        }
        revalidate();
        repaint();
    }

    public void setItems(@NotNull List<T> items) {
        this.all = new ArrayList<>(items);
        refilter();
    }

    @SuppressWarnings("unchecked")
    public @Nullable T getSelectedItem() {
        return (T) combo.getSelectedItem();
    }

    public void setSelectedItem(@Nullable T v) {
        combo.setSelectedItem(v);
    }

    public void addActionListener(@NotNull java.awt.event.ActionListener l) {
        combo.addActionListener(event -> {
            if (!updatingModel) {
                l.actionPerformed(event);
            }
        });
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        search.setEnabled(enabled);
        combo.setEnabled(enabled);
        searchToggleButton.setEnabled(enabled);
    }

    @Override
    public Dimension getMinimumSize() {
        Dimension minimumSize = super.getMinimumSize();
        int minimumWidth = JBUI.scale(120);
        if (minimumSize.width < minimumWidth) {
            minimumSize.width = minimumWidth;
        }
        return minimumSize;
    }

    private void refilter() {
        String q = StringUtil.toLowerCase(search.getText().trim());
        updatingModel = true;
        try {
            model.removeAllElements();
            for (T item : all) {
                String s;
                if (item == null) {
                    s = "";
                } else {
                    s = StringUtil.toLowerCase(text.apply(item));
                }
                if (q.isEmpty() || s.contains(q)) {
                    model.addElement(item);
                }
            }
            if (model.getSize() > 0 && combo.getSelectedItem() == null) {
                combo.setSelectedIndex(0);
            }
        } finally {
            updatingModel = false;
        }
    }
}
