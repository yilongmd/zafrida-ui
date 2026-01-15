package com.zafrida.ui.ui.components;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
/**
 * [UI工具] Swing DocumentListener 的 Lambda 包装器。
 * <p>
 * <strong>作用：</strong>
 * 简化对文本框内容变更的监听。将 {@code insert/remove/changed} 三个事件统一合并为一个 {@link Runnable} 回调。
 */
public final class SimpleDocumentListener implements DocumentListener {
    private final Runnable onChange;
    public SimpleDocumentListener(Runnable onChange) { this.onChange = onChange; }
    @Override public void insertUpdate(DocumentEvent e) { onChange.run(); }
    @Override public void removeUpdate(DocumentEvent e) { onChange.run(); }
    @Override public void changedUpdate(DocumentEvent e) { onChange.run(); }
}
