package com.zafrida.ui.ui.components;

import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SearchableComboBoxPanelTest {

    @Test
    void searchIsCollapsedByDefaultAndExpandsPanelOnDemand() throws Exception {
        AtomicBoolean initiallyVisible = new AtomicBoolean();
        AtomicInteger collapsedMinimumHeight = new AtomicInteger();
        AtomicInteger expandedMinimumHeight = new AtomicInteger();

        SwingUtilities.invokeAndWait(() -> {
            SearchableComboBoxPanel<String> panel = new SearchableComboBoxPanel<>(value -> value);
            initiallyVisible.set(panel.isSearchVisible());
            collapsedMinimumHeight.set(panel.getMinimumSize().height);
            panel.setSearchVisible(true);
            expandedMinimumHeight.set(panel.getMinimumSize().height);
        });

        assertFalse(initiallyVisible.get());
        assertTrue(expandedMinimumHeight.get() > collapsedMinimumHeight.get());
    }
}
