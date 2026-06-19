package com.mcpscanner.ui.widgets;

import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class HeaderTableModelTest {

    @Test
    void addRowAppendsEmptyRow() {
        HeaderTableModel model = new HeaderTableModel();

        model.addRow();

        assertThat(model.getRowCount()).isEqualTo(1);
        assertThat(model.getValueAt(0, 0)).isEqualTo("");
        assertThat(model.getValueAt(0, 1)).isEqualTo("");
    }

    @Test
    void setHeadersReplacesContents() {
        HeaderTableModel model = new HeaderTableModel();
        model.addRow();
        model.setValueAt("stale", 0, 0);

        Map<String, String> replacement = new LinkedHashMap<>();
        replacement.put("X-Api-Key", "secret");
        replacement.put("X-Custom", "value");
        model.setHeaders(replacement);

        assertThat(model.getRowCount()).isEqualTo(2);
        assertThat(model.headers())
                .containsEntry("X-Api-Key", "secret")
                .containsEntry("X-Custom", "value");
    }

    @Test
    void headersSkipsBlankKeys() {
        HeaderTableModel model = new HeaderTableModel();
        model.addRow();
        model.addRow();
        model.addRow();
        model.setValueAt("X-Real", 0, 0);
        model.setValueAt("real-value", 0, 1);
        model.setValueAt("   ", 1, 0);
        model.setValueAt("orphaned", 1, 1);
        model.setValueAt("", 2, 0);
        model.setValueAt("also-orphaned", 2, 1);

        Map<String, String> headers = model.headers();

        assertThat(headers).hasSize(1).containsEntry("X-Real", "real-value");
    }

    @Test
    void headersPreservesInsertionOrder() {
        HeaderTableModel model = new HeaderTableModel();
        model.addRow();
        model.addRow();
        model.setValueAt("First", 0, 0);
        model.setValueAt("1", 0, 1);
        model.setValueAt("Second", 1, 0);
        model.setValueAt("2", 1, 1);

        assertThat(model.headers().keySet()).containsExactly("First", "Second");
    }

    @Test
    void removeRowDeletesEntry() {
        HeaderTableModel model = new HeaderTableModel();
        model.addRow();
        model.addRow();
        model.setValueAt("Keep", 0, 0);
        model.setValueAt("kv", 0, 1);
        model.setValueAt("Drop", 1, 0);
        model.setValueAt("dv", 1, 1);

        model.removeRow(1);

        assertThat(model.getRowCount()).isEqualTo(1);
        assertThat(model.headers()).containsOnlyKeys("Keep");
    }
}
