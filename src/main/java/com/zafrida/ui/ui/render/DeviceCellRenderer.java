package com.zafrida.ui.ui.render;

import com.intellij.ui.ColoredListCellRenderer;
import com.intellij.ui.SimpleTextAttributes;
import com.zafrida.ui.frida.FridaDevice;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JList;
/**
 * [UI组件] 设备列表渲染器。
 * <p>
 * <strong>显示格式：</strong>
 * <b>[Type]</b> Name (ID/Host)
 * <br>例如：<b>[usb]</b> Pixel 6 (127.0.0.1:5555)
 * <p>
 * 用于 {@link com.zafrida.ui.ui.ZaFridaRunPanel} 中的设备下拉框。
 */
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
        String suffix = value.getHost() != null ? value.getHost() : value.getId();
        append("(" + suffix + ")", SimpleTextAttributes.GRAYED_ATTRIBUTES);
    }
}
