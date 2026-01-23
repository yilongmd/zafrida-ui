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
    /** 文本变化回调 */
    private final Runnable onChange;

    /**
     * 构造函数。
     * @param onChange 文本变化回调
     */
    public SimpleDocumentListener(Runnable onChange) {
        this.onChange = onChange;
    }

    /**
     * 插入更新回调。
     * @param e 事件
     */
    @Override
    public void insertUpdate(DocumentEvent e) {
        onChange.run();
    }

    /**
     * 删除更新回调。
     * @param e 事件
     */
    @Override
    public void removeUpdate(DocumentEvent e) {
        onChange.run();
    }

    /**
     * 样式更新回调。
     * @param e 事件
     */
    @Override
    public void changedUpdate(DocumentEvent e) {
        onChange.run();
    }
}
