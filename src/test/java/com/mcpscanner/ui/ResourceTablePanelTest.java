package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpResourceDefinition;
import org.junit.jupiter.api.Test;

import javax.swing.JComponent;
import javax.swing.JTable;
import java.awt.Component;
import java.util.List;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

class ResourceTablePanelTest {

    private final ResourceTablePanel panel = new ResourceTablePanel();

    @Test
    void populateSetsRowCount() {
        panel.populate(createResources(3));

        assertThat(panel.getTableModel().getRowCount()).isEqualTo(3);
    }

    @Test
    void populateWithEmptyListClearsRows() {
        panel.populate(createResources(4));
        panel.populate(List.of());

        assertThat(panel.getTableModel().getRowCount()).isZero();
    }

    @Test
    void populateDefaultsAllRowsToSelected() {
        List<McpResourceDefinition> resources = createResources(3);

        panel.populate(resources);

        assertThat(panel.selectedResources()).isEqualTo(resources);
    }

    @Test
    void deselectingRowExcludesItFromSelectedResources() {
        List<McpResourceDefinition> resources = createResources(3);
        panel.populate(resources);

        panel.getTableModel().setValueAt(false, 1, 0);

        assertThat(panel.selectedResources())
                .containsExactly(resources.get(0), resources.get(2));
    }

    @Test
    void selectingRowPopulatesDetailPanel() {
        McpResourceDefinition resource = new McpResourceDefinition(
                "docs://test", "Test", "A test resource", "text/plain");
        panel.populate(List.of(resource));

        panel.getTableForTest().setRowSelectionInterval(0, 0);

        ResourceTablePanel.ResourceDetailPanel detail = panel.getDetailPanelForTest();
        assertThat(detail.uriLabelForTest().getText()).isEqualTo("docs://test");
        assertThat(detail.nameLabelForTest().getText()).isEqualTo("Test");
        assertThat(detail.mimeTypeLabelForTest().getText()).isEqualTo("text/plain");
        assertThat(detail.descriptionAreaForTest().getText()).isEqualTo("A test resource");
    }

    @Test
    void detailLabelsDisableHtmlRendering() {
        panel.populate(List.of(new McpResourceDefinition(
                "<html>u", "<html>n", "d", "<html>m")));

        panel.getTableForTest().setRowSelectionInterval(0, 0);

        ResourceTablePanel.ResourceDetailPanel detail = panel.getDetailPanelForTest();
        assertThat(detail.uriLabelForTest().getClientProperty("html.disable")).isEqualTo(Boolean.TRUE);
        assertThat(detail.nameLabelForTest().getClientProperty("html.disable")).isEqualTo(Boolean.TRUE);
        assertThat(detail.mimeTypeLabelForTest().getClientProperty("html.disable")).isEqualTo(Boolean.TRUE);
    }

    @Test
    void nameColumnRendererDisablesHtmlRendering() {
        panel.populate(List.of(new McpResourceDefinition(
                "docs://x", "<html><img src=http://x>", "d", "text/plain")));

        JTable table = panel.getTableForTest();
        int column = SelectableInventoryTableModel.SELECT_COLUMN_INDEX + 1;
        Component component = table.getCellRenderer(0, column).getTableCellRendererComponent(
                table, table.getValueAt(0, column), false, false, 0, column);

        assertThat(((JComponent) component).getClientProperty("html.disable")).isEqualTo(Boolean.TRUE);
    }

    private List<McpResourceDefinition> createResources(int count) {
        return IntStream.range(0, count)
                .mapToObj(i -> new McpResourceDefinition(
                        "docs://r" + i, "Name " + i, "Description " + i, "text/plain"))
                .toList();
    }
}
