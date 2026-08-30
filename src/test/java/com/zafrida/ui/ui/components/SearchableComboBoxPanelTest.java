package com.zafrida.ui.ui.components;

import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Dimension;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SearchableComboBoxPanelTest {

    @Test
    void minimumHeightKeepsSearchAndComboVisible() throws Exception {
        AtomicInteger componentCount = new AtomicInteger();
        AtomicInteger childrenMinimumHeight = new AtomicInteger();
        AtomicReference<Dimension> panelMinimumSize = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            SearchableComboBoxPanel<String> panel = new SearchableComboBoxPanel<>(value -> value);
            Component[] components = panel.getComponents();
            componentCount.set(components.length);
            int minimumHeight = 0;
            for (Component component : components) {
                minimumHeight += component.getMinimumSize().height;
            }
            childrenMinimumHeight.set(minimumHeight);
            panelMinimumSize.set(panel.getMinimumSize());
        });

        assertEquals(2, componentCount.get());
        assertTrue(panelMinimumSize.get().height >= childrenMinimumHeight.get());
    }
}
