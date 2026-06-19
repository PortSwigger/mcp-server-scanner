package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpResourceDefinition;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

class ResourceTableModelTest {

    private final ResourceTableModel model = new ResourceTableModel();

    @Test
    void populateAddsRows() {
        model.populate(createResources(3));

        assertThat(model.getRowCount()).isEqualTo(3);
    }

    @Test
    void populateReplacesPreviousRows() {
        model.populate(createResources(5));
        model.populate(createResources(2));

        assertThat(model.getRowCount()).isEqualTo(2);
    }

    @Test
    void getValueAtReturnsCorrectColumn() {
        McpResourceDefinition resource = new McpResourceDefinition(
                "docs://readme", "Readme", "Server overview", "text/plain");
        model.populate(List.of(resource));

        assertThat(model.getValueAt(0, 0)).isEqualTo(Boolean.TRUE);
        assertThat(model.getValueAt(0, 1)).isEqualTo("docs://readme");
        assertThat(model.getValueAt(0, 2)).isEqualTo("Readme");
        assertThat(model.getValueAt(0, 3)).isEqualTo("Server overview");
        assertThat(model.getValueAt(0, 4)).isEqualTo("text/plain");
    }

    @Test
    void columnNamesMatch() {
        assertThat(model.getColumnCount()).isEqualTo(5);
        assertThat(model.getColumnName(0)).isEqualTo("Select");
        assertThat(model.getColumnName(1)).isEqualTo("URI");
        assertThat(model.getColumnName(2)).isEqualTo("Name");
        assertThat(model.getColumnName(3)).isEqualTo("Description");
        assertThat(model.getColumnName(4)).isEqualTo("MIME Type");
    }

    @Test
    void onlySelectColumnIsEditable() {
        model.populate(createResources(1));

        assertThat(model.isCellEditable(0, 0)).isTrue();
        for (int column = 1; column < model.getColumnCount(); column++) {
            assertThat(model.isCellEditable(0, column))
                    .as("column %d should not be editable", column)
                    .isFalse();
        }
    }

    @Test
    void populateDefaultsAllRowsToSelected() {
        List<McpResourceDefinition> resources = createResources(3);
        model.populate(resources);

        assertThat(model.selectedItems()).isEqualTo(resources);
    }

    @Test
    void deselectingRowExcludesItFromSelectedItems() {
        List<McpResourceDefinition> resources = createResources(3);
        model.populate(resources);

        model.setValueAt(false, 1, 0);

        assertThat(model.selectedItems()).containsExactly(resources.get(0), resources.get(2));
    }

    @Test
    void rowAtReturnsRow() {
        List<McpResourceDefinition> resources = createResources(2);
        model.populate(resources);

        assertThat(model.rowAt(0)).isEqualTo(resources.get(0));
        assertThat(model.rowAt(1)).isEqualTo(resources.get(1));
    }

    @Test
    void rowAtOutOfBoundsReturnsNull() {
        model.populate(createResources(1));

        assertThat(model.rowAt(-1)).isNull();
        assertThat(model.rowAt(5)).isNull();
    }

    private List<McpResourceDefinition> createResources(int count) {
        return IntStream.range(0, count)
                .mapToObj(i -> new McpResourceDefinition(
                        "docs://r" + i, "Name " + i, "Description " + i, "text/plain"))
                .toList();
    }
}
