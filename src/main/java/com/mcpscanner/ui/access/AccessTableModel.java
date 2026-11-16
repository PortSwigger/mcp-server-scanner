package com.mcpscanner.ui.access;

import com.mcpscanner.access.AccessRow;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.Principal;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.BiConsumer;

final class AccessTableModel extends AbstractTableModel {

    private final BiConsumer<AccessItemKey, AccessExpectation> expectationEdits;
    private List<AccessColumn> columns = columnsFor(List.of(), Set.of());
    private List<AccessRow> rows = List.of();

    AccessTableModel(BiConsumer<AccessItemKey, AccessExpectation> expectationEdits) {
        this.expectationEdits = expectationEdits;
    }

    void show(List<Principal> principals, List<AccessRow> visibleRows, Set<String> usersWithoutIds) {
        List<AccessColumn> next = columnsFor(principals, usersWithoutIds);
        boolean structureChanged = !next.equals(columns);
        columns = next;
        rows = List.copyOf(visibleRows);
        if (structureChanged) {
            fireTableStructureChanged();
        } else {
            fireTableDataChanged();
        }
    }

    AccessRow rowAt(int index) {
        return rows.get(index);
    }

    AccessColumn columnAt(int index) {
        return columns.get(index);
    }

    int expectationColumn() {
        return columns.size() - 1;
    }

    @Override
    public int getRowCount() {
        return rows.size();
    }

    @Override
    public int getColumnCount() {
        return columns.size();
    }

    @Override
    public String getColumnName(int column) {
        return columns.get(column).title();
    }

    @Override
    public Class<?> getColumnClass(int column) {
        return AccessRow.class;
    }

    @Override
    public Object getValueAt(int row, int column) {
        return rows.get(row);
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return columns.get(column) instanceof AccessColumn.Expectation;
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        if (value instanceof AccessExpectation expectation && isCellEditable(row, column)) {
            expectationEdits.accept(rows.get(row).item().key(), expectation);
        }
    }

    private static List<AccessColumn> columnsFor(List<Principal> principals, Set<String> usersWithoutIds) {
        List<AccessColumn> columns = new ArrayList<>();
        columns.add(new AccessColumn.Item());
        principals.forEach(principal -> columns.add(
                new AccessColumn.Identity(principal, usersWithoutIds.contains(principal.id()))));
        columns.add(new AccessColumn.Anonymous());
        columns.add(new AccessColumn.Expectation());
        return columns;
    }
}
