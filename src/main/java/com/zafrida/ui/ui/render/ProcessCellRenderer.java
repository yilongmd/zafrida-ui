package com.zafrida.ui.ui.render;

import com.intellij.ui.ColoredListCellRenderer;
import com.intellij.ui.SimpleTextAttributes;
import com.zafrida.ui.frida.FridaProcess;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JList;
/**
 * [UI组件] 进程列表渲染器。
 * <p>
 * <strong>显示格式：</strong>
 * <b>PID</b> Name (Identifier)
 * <br>例如：<b>1234</b> com.whatsapp (WhatsApp)
 * <p>
 * 用于 {@link com.zafrida.ui.fridaproject.ui.ZaFridaProjectSettingsDialog} 中的目标选择下拉框。
 */
public final class ProcessCellRenderer extends ColoredListCellRenderer<FridaProcess> {
    /**
     * 渲染进程下拉项。
     */
    @Override
    protected void customizeCellRenderer(@NotNull JList<? extends FridaProcess> list,
                                         @Nullable FridaProcess value,
                                         int index,
                                         boolean selected,
                                         boolean hasFocus) {
        if (value == null) {
            append("(null)", SimpleTextAttributes.ERROR_ATTRIBUTES);
            return;
        }

        String pidText = value.getPid() != null ? String.valueOf(value.getPid()) : "-";
        append(pidText, SimpleTextAttributes.REGULAR_BOLD_ATTRIBUTES);
        append("  ");
        append(value.getName(), SimpleTextAttributes.REGULAR_ATTRIBUTES);

        if (value.getIdentifier() != null && !value.getIdentifier().isBlank()) {
            append("  ");
            append(value.getIdentifier(), SimpleTextAttributes.GRAYED_ATTRIBUTES);
        }
    }
}
