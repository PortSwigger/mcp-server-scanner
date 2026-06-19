package com.mcpscanner.ui;

import javax.swing.JComponent;

public interface InventoryDetailPanel<T> {
    JComponent component();
    void show(T item);
    void clear();
}
