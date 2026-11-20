package com.mcpscanner.ui;

import com.mcpscanner.auth.oauth.ScopeSelection;
import com.mcpscanner.config.ExtensionConfigStore.PersistedScope;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public final class ScopeTableModel extends AbstractTableModel {

    private static final String SOURCE_DISCOVERED = "discovered";
    private static final String SOURCE_CUSTOM = "custom";
    private static final String[] COLUMN_NAMES = {"Enabled", "Scope", "Source"};
    static final int COLUMN_ENABLED = 0;
    static final int COLUMN_NAME = 1;
    static final int COLUMN_SOURCE = 2;

    private final List<PersistedScope> rows = new ArrayList<>();

    static PersistedScope customScope(String name) {
        return new PersistedScope(name, true, SOURCE_CUSTOM);
    }

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
    public Class<?> getColumnClass(int columnIndex) {
        return columnIndex == COLUMN_ENABLED ? Boolean.class : String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        PersistedScope scope = rows.get(rowIndex);
        return switch (columnIndex) {
            case COLUMN_ENABLED -> scope.enabled();
            case COLUMN_NAME -> scope.name();
            case COLUMN_SOURCE -> scope.source();
            default -> throw new IndexOutOfBoundsException("Column " + columnIndex);
        };
    }

    @Override
    public boolean isCellEditable(int rowIndex, int columnIndex) {
        return switch (columnIndex) {
            case COLUMN_ENABLED -> true;
            case COLUMN_NAME -> isCustomRow(rowIndex);
            default -> false;
        };
    }

    @Override
    public void setValueAt(Object value, int rowIndex, int columnIndex) {
        PersistedScope existing = rows.get(rowIndex);
        PersistedScope updated = switch (columnIndex) {
            case COLUMN_ENABLED -> new PersistedScope(existing.name(), (Boolean) value, existing.source());
            case COLUMN_NAME -> renameCustom(existing, value);
            default -> existing;
        };
        rows.set(rowIndex, updated);
        fireTableRowsUpdated(rowIndex, rowIndex);
    }

    public PersistedScope scopeAt(int row) {
        return rows.get(row);
    }

    public List<String> scopeNames() {
        return rows.stream().map(PersistedScope::name).toList();
    }

    public List<String> enabledScopes() {
        return rows.stream().filter(PersistedScope::enabled).map(PersistedScope::name).toList();
    }

    public ScopeSelection scopeSelection() {
        return new ScopeSelection(declinedScopes(), tickedCustomScopes());
    }

    private Set<String> declinedScopes() {
        return rows.stream().filter(scope -> !scope.enabled()).map(PersistedScope::name).collect(Collectors.toSet());
    }

    private List<String> tickedCustomScopes() {
        return rows.stream().filter(scope -> isCustom(scope) && scope.enabled()).map(PersistedScope::name).toList();
    }

    public void addCustomScope(String name) {
        if (name == null) {
            return;
        }
        String trimmed = name.trim();
        if (trimmed.isEmpty() || containsName(trimmed)) {
            return;
        }
        rows.add(customScope(trimmed));
        int inserted = rows.size() - 1;
        fireTableRowsInserted(inserted, inserted);
    }

    public void removeRow(int row) {
        if (!isCustomRow(row)) {
            throw new IllegalStateException("Only custom rows can be removed");
        }
        rows.remove(row);
        fireTableRowsDeleted(row, row);
    }

    public void removeLastCustomRow() {
        for (int row = rows.size() - 1; row >= 0; row--) {
            if (isCustomRow(row)) {
                rows.remove(row);
                fireTableRowsDeleted(row, row);
                return;
            }
        }
    }

    public void replaceDiscovered(List<String> discoveredScopeNames) {
        List<PersistedScope> custom = rows.stream().filter(this::isCustom).toList();
        List<PersistedScope> discovered = discoveredScopeNames.stream().distinct()
                .filter(name -> custom.stream().noneMatch(scope -> scope.name().equals(name)))
                .map(this::discoveredRow)
                .toList();
        rows.clear();
        rows.addAll(discovered);
        rows.addAll(custom);
        fireTableDataChanged();
    }

    private PersistedScope discoveredRow(String name) {
        return rows.stream().filter(scope -> scope.name().equals(name)).findFirst()
                .orElseGet(() -> new PersistedScope(name, true, SOURCE_DISCOVERED));
    }

    public boolean removeDiscovered() {
        boolean removed = rows.removeIf(scope -> !isCustom(scope));
        if (removed) {
            fireTableDataChanged();
        }
        return removed;
    }

    public void seed(List<PersistedScope> persistedScopes) {
        rows.clear();
        rows.addAll(persistedScopes);
        fireTableDataChanged();
    }

    public void setEnabled(int row, boolean enabled) {
        PersistedScope existing = rows.get(row);
        rows.set(row, new PersistedScope(existing.name(), enabled, existing.source()));
        fireTableCellUpdated(row, COLUMN_ENABLED);
    }

    public List<PersistedScope> scopesSnapshot() {
        return List.copyOf(rows);
    }

    boolean isCustomRow(int row) {
        return isCustom(rows.get(row));
    }

    private boolean isCustom(PersistedScope scope) {
        return SOURCE_CUSTOM.equals(scope.source());
    }

    private boolean containsName(String name) {
        return rows.stream().anyMatch(scope -> scope.name().equals(name));
    }

    private PersistedScope renameCustom(PersistedScope existing, Object value) {
        if (value == null) {
            return existing;
        }
        String trimmed = value.toString().trim();
        if (trimmed.isEmpty() || containsName(trimmed)) {
            return existing;
        }
        return new PersistedScope(trimmed, existing.enabled(), existing.source());
    }
}
