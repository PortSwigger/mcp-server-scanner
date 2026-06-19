package com.mcpscanner.ui;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

public abstract class SelectableInventoryTableModel<T>
        extends AbstractTableModel
        implements InventoryTableModel<T> {

    static final int SELECT_COLUMN_INDEX = 0;
    private static final String SELECT_COLUMN_NAME = "Select";

    private final List<SelectableRow<T>> rows = new ArrayList<>();

    protected abstract String[] extraColumnNames();

    protected abstract Object extraValueAt(T item, int extraColumnIndex);

    @Override
    public final int getRowCount() {
        return rows.size();
    }

    @Override
    public final int getColumnCount() {
        return extraColumnNames().length + 1;
    }

    @Override
    public final String getColumnName(int column) {
        if (column == SELECT_COLUMN_INDEX) {
            return SELECT_COLUMN_NAME;
        }
        return extraColumnNames()[column - 1];
    }

    @Override
    public final Class<?> getColumnClass(int column) {
        if (column == SELECT_COLUMN_INDEX) {
            return Boolean.class;
        }
        return String.class;
    }

    @Override
    public final boolean isCellEditable(int row, int column) {
        return column == SELECT_COLUMN_INDEX;
    }

    @Override
    public final Object getValueAt(int row, int column) {
        SelectableRow<T> entry = rows.get(row);
        if (column == SELECT_COLUMN_INDEX) {
            return entry.selected;
        }
        return extraValueAt(entry.item, column - 1);
    }

    @Override
    public final void setValueAt(Object value, int row, int column) {
        if (column == SELECT_COLUMN_INDEX && value instanceof Boolean checked) {
            rows.get(row).selected = checked;
            fireTableCellUpdated(row, column);
        }
    }

    @Override
    public final void populate(List<T> items) {
        rows.clear();
        for (T item : items) {
            rows.add(new SelectableRow<>(item, true));
        }
        fireTableDataChanged();
    }

    @Override
    public final T rowAt(int modelRow) {
        if (modelRow < 0 || modelRow >= rows.size()) {
            return null;
        }
        return rows.get(modelRow).item;
    }

    public final List<T> selectedItems() {
        List<T> result = new ArrayList<>();
        for (SelectableRow<T> entry : rows) {
            if (entry.selected) {
                result.add(entry.item);
            }
        }
        return result;
    }

    public final boolean isSelected(int modelRow) {
        if (modelRow < 0 || modelRow >= rows.size()) {
            return false;
        }
        return rows.get(modelRow).selected;
    }

    public final int selectedCount() {
        int count = 0;
        for (SelectableRow<T> entry : rows) {
            if (entry.selected) {
                count++;
            }
        }
        return count;
    }

    private static final class SelectableRow<T> {
        final T item;
        boolean selected;

        SelectableRow(T item, boolean selected) {
            this.item = item;
            this.selected = selected;
        }
    }
}
