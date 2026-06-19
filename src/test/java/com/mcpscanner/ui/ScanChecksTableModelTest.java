package com.mcpscanner.ui;

import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import com.mcpscanner.checks.registry.CheckDescriptor;
import com.mcpscanner.checks.registry.ManagedCheck;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ScanChecksTableModelTest {

    private static final ManagedCheck TOOL_ENUM = stubCheck(
            new CheckDescriptor("tool-enum", "Tool Enumeration", "desc-1",
                    AuditIssueSeverity.MEDIUM, ScanCheckType.PER_HOST, true, List.of()));
    private static final ManagedCheck SCHEMA_BYPASS = stubCheck(
            new CheckDescriptor("schema-bypass", "Schema Bypass", "desc-2",
                    AuditIssueSeverity.MEDIUM, ScanCheckType.PER_REQUEST, true, List.of()));
    private static final ManagedCheck AUTH_BYPASS = stubCheck(
            new CheckDescriptor("auth-bypass", "Auth Bypass", "desc-3",
                    AuditIssueSeverity.HIGH, ScanCheckType.PER_REQUEST, true, List.of()));

    private ScanCheckSettings settings;
    private ScanChecksTableModel model;

    @BeforeEach
    void setUp() {
        settings = mock(ScanCheckSettings.class);
        model = new ScanChecksTableModel(List.of(TOOL_ENUM, SCHEMA_BYPASS, AUTH_BYPASS), settings);
    }

    @Test
    void rowCountMatchesUnderlyingList() {
        assertThat(model.getRowCount()).isEqualTo(3);
    }

    @Test
    void columnCountIsFour() {
        assertThat(model.getColumnCount()).isEqualTo(4);
    }

    @Test
    void columnHeadersAreEnabledNameSeverityScope() {
        assertThat(model.getColumnName(0)).isEqualTo("Enabled");
        assertThat(model.getColumnName(1)).isEqualTo("Name");
        assertThat(model.getColumnName(2)).isEqualTo("Severity");
        assertThat(model.getColumnName(3)).isEqualTo("Scope");
    }

    @Test
    void enabledColumnIsBooleanClass() {
        assertThat(model.getColumnClass(ScanChecksTableModel.COLUMN_ENABLED))
                .isEqualTo(Boolean.class);
    }

    @Test
    void severityColumnIsAuditIssueSeverityClass() {
        assertThat(model.getColumnClass(ScanChecksTableModel.COLUMN_SEVERITY))
                .isEqualTo(AuditIssueSeverity.class);
    }

    @Test
    void onlyEnabledColumnIsEditable() {
        assertThat(model.isCellEditable(0, ScanChecksTableModel.COLUMN_ENABLED)).isTrue();
        assertThat(model.isCellEditable(0, ScanChecksTableModel.COLUMN_NAME)).isFalse();
        assertThat(model.isCellEditable(0, ScanChecksTableModel.COLUMN_SEVERITY)).isFalse();
        assertThat(model.isCellEditable(0, ScanChecksTableModel.COLUMN_SCOPE)).isFalse();
    }

    @Test
    void enabledValueComesFromSettingsWithDescriptorDefault() {
        when(settings.isEnabled("tool-enum", true)).thenReturn(false);

        Object value = model.getValueAt(0, ScanChecksTableModel.COLUMN_ENABLED);

        assertThat(value).isEqualTo(false);
        verify(settings).isEnabled("tool-enum", true);
    }

    @Test
    void nameValueIsDescriptorDisplayName() {
        assertThat(model.getValueAt(0, ScanChecksTableModel.COLUMN_NAME))
                .isEqualTo("Tool Enumeration");
    }

    @Test
    void severityValueIsTheRawEnum() {
        assertThat(model.getValueAt(2, ScanChecksTableModel.COLUMN_SEVERITY))
                .isEqualTo(AuditIssueSeverity.HIGH);
    }

    @Test
    void scopeIsFormattedAsPerHost() {
        assertThat(model.getValueAt(0, ScanChecksTableModel.COLUMN_SCOPE))
                .isEqualTo("Per host");
    }

    @Test
    void scopeIsFormattedAsPerRequest() {
        assertThat(model.getValueAt(1, ScanChecksTableModel.COLUMN_SCOPE))
                .isEqualTo("Per request");
    }

    @Test
    void setValueAtPersistsThroughSettingsAndFiresRowEvent() {
        List<TableModelEvent> events = captureEvents();

        model.setValueAt(false, 1, ScanChecksTableModel.COLUMN_ENABLED);

        verify(settings).setEnabled("schema-bypass", false);
        assertThat(events).hasSize(1);
        TableModelEvent event = events.get(0);
        assertThat(event.getType()).isEqualTo(TableModelEvent.UPDATE);
        assertThat(event.getFirstRow()).isEqualTo(1);
        assertThat(event.getLastRow()).isEqualTo(1);
    }

    @Test
    void setValueAtIgnoresNonEditableColumn() {
        List<TableModelEvent> events = captureEvents();

        model.setValueAt("anything", 0, ScanChecksTableModel.COLUMN_NAME);

        assertThat(events).isEmpty();
    }

    @Test
    void checkAtReturnsManagedCheckAtRow() {
        assertThat(model.checkAt(0)).isSameAs(TOOL_ENUM);
        assertThat(model.checkAt(1)).isSameAs(SCHEMA_BYPASS);
        assertThat(model.checkAt(2)).isSameAs(AUTH_BYPASS);
    }

    @Test
    void checkAtReturnsNullForOutOfRangeRow() {
        assertThat(model.checkAt(-1)).isNull();
        assertThat(model.checkAt(99)).isNull();
    }

    @Test
    void rowForIdLocatesCheckById() {
        assertThat(model.rowForId("auth-bypass")).isEqualTo(2);
        assertThat(model.rowForId("missing")).isEqualTo(-1);
    }

    private List<TableModelEvent> captureEvents() {
        List<TableModelEvent> events = new ArrayList<>();
        TableModelListener listener = events::add;
        model.addTableModelListener(listener);
        return events;
    }

    private static ManagedCheck stubCheck(CheckDescriptor descriptor) {
        return new ManagedCheck() {
            @Override
            public CheckDescriptor descriptor() {
                return descriptor;
            }

            @Override
            public void registerWith(Scanner scanner) {
                // no-op for tests
            }
        };
    }
}
