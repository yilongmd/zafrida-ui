package com.zafrida.ui.ui.render;

import com.intellij.ui.ColoredListCellRenderer;
import com.intellij.ui.SimpleTextAttributes;
import com.zafrida.ui.frida.FridaDevice;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JList;

public final class DeviceCellRenderer extends ColoredListCellRenderer<FridaDevice> {

    @Override
    protected void customizeCellRenderer(@NotNull JList<? extends FridaDevice> list,
                                         @Nullable FridaDevice value,
                                         int index,
                                         boolean selected,
                                         boolean hasFocus) {
        if (value == null) {
            append("(null)", SimpleTextAttributes.ERROR_ATTRIBUTES);
            return;
        }

        append(value.getType(), SimpleTextAttributes.REGULAR_BOLD_ATTRIBUTES);
        append("  ");
        append(value.getName(), SimpleTextAttributes.REGULAR_ATTRIBUTES);
        append("  ");
        String suffix = value.getId();
        if (value.getHost() != null) {
            suffix = value.getHost();
        }
        append(String.format("(%s)", suffix), SimpleTextAttributes.GRAYED_ATTRIBUTES);
    }
}
