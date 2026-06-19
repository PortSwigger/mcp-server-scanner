package com.mcpscanner.ui;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.checks.registry.CheckDescriptor;
import com.mcpscanner.checks.registry.ManagedCheck;
import com.mcpscanner.checks.registry.ScanCheckSettings;

import javax.swing.table.AbstractTableModel;
import java.util.List;
import java.util.Objects;

final class ScanChecksTableModel extends AbstractTableModel {

    static final int COLUMN_ENABLED = 0;
    static final int COLUMN_NAME = 1;
    static final int COLUMN_SEVERITY = 2;
    static final int COLUMN_SCOPE = 3;

    private static final String[] COLUMN_NAMES = {"Enabled", "Name", "Severity", "Scope"};

    private final List<ManagedCheck> checks;
    private final ScanCheckSettings settings;

    ScanChecksTableModel(List<? extends ManagedCheck> checks, ScanCheckSettings settings) {
        this.checks = List.copyOf(Objects.requireNonNull(checks, "checks must not be null"));
        this.settings = Objects.requireNonNull(settings, "settings must not be null");
    }

    @Override
    public int getRowCount() {
        return checks.size();
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
        return switch (column) {
            case COLUMN_ENABLED -> Boolean.class;
            case COLUMN_SEVERITY -> AuditIssueSeverity.class;
            default -> String.class;
        };
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return column == COLUMN_ENABLED;
    }

    @Override
    public Object getValueAt(int row, int column) {
        CheckDescriptor descriptor = checks.get(row).descriptor();
        return switch (column) {
            case COLUMN_ENABLED -> settings.isEnabled(descriptor.id(), descriptor.defaultEnabled());
            case COLUMN_NAME -> descriptor.displayName();
            case COLUMN_SEVERITY -> descriptor.headlineSeverity();
            case COLUMN_SCOPE -> formatScope(descriptor.scope());
            default -> null;
        };
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        if (column != COLUMN_ENABLED || !(value instanceof Boolean enabled)) {
            return;
        }
        CheckDescriptor descriptor = checks.get(row).descriptor();
        settings.setEnabled(descriptor.id(), enabled);
        fireTableRowsUpdated(row, row);
    }

    ManagedCheck checkAt(int row) {
        if (row < 0 || row >= checks.size()) {
            return null;
        }
        return checks.get(row);
    }

    int rowForId(String id) {
        for (int row = 0; row < checks.size(); row++) {
            if (checks.get(row).descriptor().id().equals(id)) {
                return row;
            }
        }
        return -1;
    }

    private static String formatScope(ScanCheckType scope) {
        return switch (scope) {
            case PER_HOST -> "Per host";
            case PER_REQUEST -> "Per request";
            case PER_INSERTION_POINT -> "Per insertion point";
        };
    }
}
