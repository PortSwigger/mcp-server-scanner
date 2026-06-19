package com.mcpscanner.ui;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.registry.ScanCheckRegistry;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JTable;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import java.util.List;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScanChecksPanelTest {

    private ScanCheckSettings settings;
    private ScanCheckRegistry registry;

    @BeforeEach
    void setUp() {
        settings = mock(ScanCheckSettings.class);
        when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        Supplier<AuthStrategy> authSupplier = NoAuthStrategy::new;
        registry = new ScanCheckRegistry(authSupplier, settings);
    }

    @Test
    void defaultSortPlacesHighestSeverityFirst() {
        ScanChecksPanel panel = new ScanChecksPanel(registry, settings);
        JTable table = panel.tableForTest();

        AuditIssueSeverity first = severityAtView(table, 0);

        assertThat(first).isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void severityColumnSortKeyIsDescendingByDefault() {
        ScanChecksPanel panel = new ScanChecksPanel(registry, settings);
        JTable table = panel.tableForTest();

        List<? extends RowSorter.SortKey> keys = table.getRowSorter().getSortKeys();

        assertThat(keys).hasSize(1);
        assertThat(keys.get(0).getColumn()).isEqualTo(ScanChecksTableModel.COLUMN_SEVERITY);
        assertThat(keys.get(0).getSortOrder()).isEqualTo(SortOrder.DESCENDING);
    }

    @Test
    void clickingSeverityHeaderReversesSort() {
        ScanChecksPanel panel = new ScanChecksPanel(registry, settings);
        JTable table = panel.tableForTest();

        table.getRowSorter().toggleSortOrder(ScanChecksTableModel.COLUMN_SEVERITY);

        assertThat(table.getRowSorter().getSortKeys().get(0).getSortOrder())
                .isEqualTo(SortOrder.ASCENDING);
        AuditIssueSeverity first = severityAtView(table, 0);
        assertThat(first).isIn(AuditIssueSeverity.INFORMATION, AuditIssueSeverity.LOW,
                AuditIssueSeverity.MEDIUM);
    }

    @Test
    void severityColumnIsNonAscendingTopToBottom() {
        ScanChecksPanel panel = new ScanChecksPanel(registry, settings);
        JTable table = panel.tableForTest();

        for (int row = 1; row < table.getRowCount(); row++) {
            int previous = rank(severityAtView(table, row - 1));
            int current = rank(severityAtView(table, row));
            assertThat(current).isLessThanOrEqualTo(previous);
        }
    }

    private static AuditIssueSeverity severityAtView(JTable table, int viewRow) {
        return (AuditIssueSeverity) table.getValueAt(viewRow, ScanChecksTableModel.COLUMN_SEVERITY);
    }

    private static int rank(AuditIssueSeverity severity) {
        return switch (severity) {
            case HIGH -> 4;
            case MEDIUM -> 3;
            case LOW -> 2;
            case INFORMATION -> 1;
            case FALSE_POSITIVE -> 0;
        };
    }
}
