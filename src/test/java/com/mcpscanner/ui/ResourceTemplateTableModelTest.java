package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

class ResourceTemplateTableModelTest {

    private final ResourceTemplateTableModel model = new ResourceTemplateTableModel();

    @Test
    void populateAddsRows() {
        model.populate(createTemplates(3));

        assertThat(model.getRowCount()).isEqualTo(3);
    }

    @Test
    void populateReplacesPreviousRows() {
        model.populate(createTemplates(5));
        model.populate(createTemplates(1));

        assertThat(model.getRowCount()).isEqualTo(1);
    }

    @Test
    void getValueAtReturnsCorrectColumn() {
        McpResourceTemplateDefinition template = new McpResourceTemplateDefinition(
                "file:///{path}", "files", "filesystem entries", "text/plain");
        model.populate(List.of(template));

        assertThat(model.getValueAt(0, 0)).isEqualTo(Boolean.TRUE);
        assertThat(model.getValueAt(0, 1)).isEqualTo("file:///{path}");
        assertThat(model.getValueAt(0, 2)).isEqualTo("files");
        assertThat(model.getValueAt(0, 3)).isEqualTo("filesystem entries");
        assertThat(model.getValueAt(0, 4)).isEqualTo("text/plain");
    }

    @Test
    void columnNamesMatch() {
        assertThat(model.getColumnCount()).isEqualTo(5);
        assertThat(model.getColumnName(0)).isEqualTo("Select");
        assertThat(model.getColumnName(1)).isEqualTo("URI Template");
        assertThat(model.getColumnName(2)).isEqualTo("Name");
        assertThat(model.getColumnName(3)).isEqualTo("Description");
        assertThat(model.getColumnName(4)).isEqualTo("MIME Type");
    }

    @Test
    void onlySelectColumnIsEditable() {
        model.populate(createTemplates(1));

        assertThat(model.isCellEditable(0, 0)).isTrue();
        for (int column = 1; column < model.getColumnCount(); column++) {
            assertThat(model.isCellEditable(0, column)).isFalse();
        }
    }

    @Test
    void populateDefaultsAllRowsToSelected() {
        List<McpResourceTemplateDefinition> templates = createTemplates(3);
        model.populate(templates);

        assertThat(model.selectedItems()).isEqualTo(templates);
    }

    @Test
    void deselectingRowExcludesItFromSelectedItems() {
        List<McpResourceTemplateDefinition> templates = createTemplates(3);
        model.populate(templates);

        model.setValueAt(false, 2, 0);

        assertThat(model.selectedItems())
                .containsExactly(templates.get(0), templates.get(1));
    }

    @Test
    void rowAtReturnsRow() {
        List<McpResourceTemplateDefinition> templates = createTemplates(2);
        model.populate(templates);

        assertThat(model.rowAt(0)).isEqualTo(templates.get(0));
        assertThat(model.rowAt(1)).isEqualTo(templates.get(1));
    }

    @Test
    void rowAtOutOfBoundsReturnsNull() {
        model.populate(createTemplates(1));

        assertThat(model.rowAt(-1)).isNull();
        assertThat(model.rowAt(5)).isNull();
    }

    private List<McpResourceTemplateDefinition> createTemplates(int count) {
        return IntStream.range(0, count)
                .mapToObj(i -> new McpResourceTemplateDefinition(
                        "tmpl://" + i, "name " + i, "desc " + i, "text/plain"))
                .toList();
    }
}
