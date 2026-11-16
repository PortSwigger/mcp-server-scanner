package com.mcpscanner.ui.access;

import com.mcpscanner.identity.MinedValue;
import com.mcpscanner.identity.OwnedValue;
import com.mcpscanner.identity.ValueScope;

import javax.swing.table.AbstractTableModel;
import java.util.List;
import java.util.Optional;

final class OwnedValuesTableModel extends AbstractTableModel {

    static final String[] COLUMNS = {"Value", "Argument", "Source", "Scope", "Origin"};
    private static final String NONE = "—";

    private List<OwnedValue> rows = List.of();

    void show(List<OwnedValue> values) {
        rows = List.copyOf(values);
        fireTableDataChanged();
    }

    Optional<OwnedValue> at(int row) {
        return row >= 0 && row < rows.size() ? Optional.of(rows.get(row)) : Optional.empty();
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Object getValueAt(int row, int column) {
        OwnedValue value = rows.get(row);
        return switch (column) {
            case 0 -> value.value();
            case 1 -> value.argument();
            case 2 -> mined(value).map(mined -> mined.source().operation() + " · " + mined.source().fieldPath())
                    .orElse(NONE);
            case 3 -> mined(value).map(mined -> scope(mined.scope())).orElse(NONE);
            default -> value instanceof MinedValue ? "Collected" : "Entered";
        };
    }

    private static Optional<MinedValue> mined(OwnedValue value) {
        return value instanceof MinedValue mined ? Optional.of(mined) : Optional.empty();
    }

    private static String scope(ValueScope scope) {
        return switch (scope) {
            case PRIVATE -> "Private";
            case ATTRIBUTED -> "Own (private marker)";
            case SHARED -> "Shared";
        };
    }
}
