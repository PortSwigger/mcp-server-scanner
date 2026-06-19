package com.mcpscanner.ui.widgets;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class HeaderTableModel extends AbstractTableModel {

    private static final String[] COLUMN_NAMES = {"Header", "Value", ""};
    private static final int COLUMN_NAME = 0;
    private static final int COLUMN_VALUE = 1;
    private static final int COLUMN_REMOVE = 2;

    private static final class HeaderEntry {
        String name;
        String value;

        HeaderEntry(String name, String value) {
            this.name = name;
            this.value = value;
        }
    }

    private final List<HeaderEntry> rows = new ArrayList<>();

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMN_NAMES.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMN_NAMES[column];
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return column == COLUMN_REMOVE ? Object.class : String.class;
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return true;
    }

    @Override
    public Object getValueAt(int row, int column) {
        HeaderEntry entry = rows.get(row);
        return switch (column) {
            case COLUMN_NAME -> entry.name;
            case COLUMN_VALUE -> entry.value;
            case COLUMN_REMOVE -> "";
            default -> null;
        };
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        HeaderEntry entry = rows.get(row);
        String text = value == null ? "" : value.toString();
        switch (column) {
            case COLUMN_NAME -> entry.name = text;
            case COLUMN_VALUE -> entry.value = text;
            default -> {
                return;
            }
        }
        fireTableRowsUpdated(row, row);
    }

    public void addRow() {
        rows.add(new HeaderEntry("", ""));
        int inserted = rows.size() - 1;
        fireTableRowsInserted(inserted, inserted);
    }

    public void removeRow(int row) {
        rows.remove(row);
        fireTableRowsDeleted(row, row);
    }

    public Map<String, String> headers() {
        Map<String, String> result = new LinkedHashMap<>();
        for (HeaderEntry entry : rows) {
            String name = entry.name == null ? "" : entry.name.trim();
            if (name.isEmpty()) {
                continue;
            }
            String value = entry.value == null ? "" : entry.value.trim();
            result.put(name, value);
        }
        return result;
    }

    public void setHeaders(Map<String, String> headers) {
        rows.clear();
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                rows.add(new HeaderEntry(entry.getKey(), entry.getValue()));
            }
        }
        fireTableDataChanged();
    }
}
