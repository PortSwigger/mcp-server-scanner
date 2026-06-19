package com.mcpscanner.ui;

import javax.swing.table.TableModel;
import java.util.List;

public interface InventoryTableModel<T> extends TableModel {
    T rowAt(int modelRow);
    void populate(List<T> items);
}
