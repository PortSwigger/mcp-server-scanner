package com.mcpscanner.ui;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ToolAnnotations;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.TableCellRenderer;
import java.awt.Color;
import java.awt.Component;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ToolTablePanelTest {

    private static final ToolAnnotations READ_ONLY =
            new ToolAnnotations(null, true, null, null, null);
    private static final ToolAnnotations DESTRUCTIVE =
            new ToolAnnotations(null, false, true, null, null);

    private final RawEditor parametersEditor = mock(RawEditor.class);
    private ToolTablePanel panel;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        when(parametersEditor.uiComponent()).thenReturn(new javax.swing.JPanel());
        UserInterface userInterface = mock(UserInterface.class);
        when(userInterface.createRawEditor(any(EditorOptions[].class))).thenReturn(parametersEditor);
        panel = new ToolTablePanel(userInterface);
    }

    @Test
    void populateSetsCorrectRowCount() {
        List<McpToolDefinition> tools = createTools(3);

        panel.populate(tools);

        assertThat(panel.getTableModel().getRowCount()).isEqualTo(3);
    }

    @Test
    void selectedToolsReturnsAllToolsWhenAllSelected() {
        List<McpToolDefinition> tools = createTools(2);
        panel.populate(tools);

        List<McpToolDefinition> selected = panel.selectedTools();

        assertThat(selected).isEqualTo(tools);
    }

    @Test
    void selectedToolsReturnsEmptyWhenNoneSelected() {
        List<McpToolDefinition> tools = createTools(2);
        panel.populate(tools);

        panel.getTableModel().setValueAt(false, 0, 0);
        panel.getTableModel().setValueAt(false, 1, 0);

        assertThat(panel.selectedTools()).isEmpty();
    }

    @Test
    void selectedToolsReturnsOnlyCheckedToolsAfterToggling() {
        List<McpToolDefinition> tools = createTools(3);
        panel.populate(tools);

        panel.getTableModel().setValueAt(false, 1, 0);

        List<McpToolDefinition> selected = panel.selectedTools();
        assertThat(selected).hasSize(2);
        assertThat(selected).containsExactly(tools.get(0), tools.get(2));
    }

    @Test
    void populateReplacesExistingData() {
        panel.populate(createTools(5));
        panel.populate(createTools(2));

        assertThat(panel.getTableModel().getRowCount()).isEqualTo(2);
        assertThat(panel.selectedTools()).hasSize(2);
    }

    @Test
    void annotationsColumnReportsReadOnly() {
        McpToolDefinition tool = annotatedTool("read", READ_ONLY);
        panel.populate(List.of(tool));

        Object value = panel.getTableModel().getValueAt(0, ToolTableModel.COLUMN_ANNOTATIONS + 1);

        assertThat(value).isEqualTo(ToolTableModel.LABEL_READ_ONLY);
    }

    @Test
    void annotationsColumnReportsDestructive() {
        McpToolDefinition tool = annotatedTool("destroy", DESTRUCTIVE);
        panel.populate(List.of(tool));

        Object value = panel.getTableModel().getValueAt(0, ToolTableModel.COLUMN_ANNOTATIONS + 1);

        assertThat(value).isEqualTo(ToolTableModel.LABEL_DESTRUCTIVE);
    }

    @Test
    void annotationsColumnReportsNotSpecified() {
        McpToolDefinition tool = annotatedTool("unknown", ToolAnnotations.EMPTY);
        panel.populate(List.of(tool));

        Object value = panel.getTableModel().getValueAt(0, ToolTableModel.COLUMN_ANNOTATIONS + 1);

        assertThat(value).isEqualTo(ToolTableModel.LABEL_NOT_SPECIFIED);
    }

    @Test
    void headerStateAllWhenEveryRowSelected() {
        ExtensionConfigStore store = stubbedConfigStore();
        panel.setSelectionPersistence(store, () -> "https://mcp.example.com/mcp");
        panel.populate(List.of(
                annotatedTool("a", READ_ONLY),
                annotatedTool("b", READ_ONLY)));

        assertThat(panel.headerStateForTest()).isEqualTo(ToolTablePanel.HeaderState.ALL);
    }

    @Test
    void headerStateNoneWhenNoRowSelected() {
        ExtensionConfigStore store = stubbedConfigStore();
        panel.setSelectionPersistence(store, () -> "https://mcp.example.com/mcp");
        panel.populate(List.of(
                annotatedTool("a", DESTRUCTIVE),
                annotatedTool("b", DESTRUCTIVE)));

        assertThat(panel.headerStateForTest()).isEqualTo(ToolTablePanel.HeaderState.NONE);
    }

    @Test
    void headerStatePartialWhenSomeRowsSelected() {
        ExtensionConfigStore store = stubbedConfigStore();
        panel.setSelectionPersistence(store, () -> "https://mcp.example.com/mcp");
        panel.populate(List.of(
                annotatedTool("a", READ_ONLY),
                annotatedTool("b", DESTRUCTIVE)));

        assertThat(panel.headerStateForTest()).isEqualTo(ToolTablePanel.HeaderState.PARTIAL);
    }

    @Test
    void headerClickToggleAllSelectsWhenPartial() {
        ExtensionConfigStore store = stubbedConfigStore();
        panel.setSelectionPersistence(store, () -> "https://mcp.example.com/mcp");
        panel.populate(List.of(
                annotatedTool("a", READ_ONLY),
                annotatedTool("b", DESTRUCTIVE)));

        panel.simulateHeaderClickForTest();

        assertThat(panel.headerStateForTest()).isEqualTo(ToolTablePanel.HeaderState.ALL);
        assertThat(panel.selectedTools()).hasSize(2);
    }

    @Test
    void headerClickToggleAllClearsWhenAllSelected() {
        ExtensionConfigStore store = stubbedConfigStore();
        panel.setSelectionPersistence(store, () -> "https://mcp.example.com/mcp");
        panel.populate(List.of(
                annotatedTool("a", READ_ONLY),
                annotatedTool("b", READ_ONLY)));

        panel.simulateHeaderClickForTest();

        assertThat(panel.headerStateForTest()).isEqualTo(ToolTablePanel.HeaderState.NONE);
        assertThat(panel.selectedTools()).isEmpty();
    }

    @Test
    void selectReadOnlyButtonChecksOnlyReadOnlyTools() {
        ExtensionConfigStore store = stubbedConfigStore();
        panel.setSelectionPersistence(store, () -> "https://mcp.example.com/mcp");
        McpToolDefinition readTool = annotatedTool("read", READ_ONLY);
        McpToolDefinition destroyTool = annotatedTool("destroy", DESTRUCTIVE);
        McpToolDefinition unknownTool = annotatedTool("unknown", ToolAnnotations.EMPTY);
        panel.populate(List.of(readTool, destroyTool, unknownTool));
        panel.simulateHeaderClickForTest();
        assertThat(panel.selectedTools()).hasSize(3);

        panel.selectReadOnlyButtonForTest().doClick();

        assertThat(panel.selectedTools()).containsExactly(readTool);
    }

    @Test
    void defaultSelectionUsesStoredPreferenceWhenPresent() {
        PersistedObject persistedStore = mock(PersistedObject.class);
        when(persistedStore.getBoolean(anyString())).thenReturn(null);
        Logging logging = mock(Logging.class);
        ExtensionConfigStore store = new ExtensionConfigStore(persistedStore, logging);
        store.setToolSelected("https://mcp.example.com/mcp", "destroy", true);
        when(persistedStore.getBoolean(anyString())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            if (key.endsWith(".tool.destroy.selected")) {
                return Boolean.TRUE;
            }
            return null;
        });

        panel.setSelectionPersistence(store, () -> "https://mcp.example.com/mcp");
        panel.populate(List.of(
                annotatedTool("read", READ_ONLY),
                annotatedTool("destroy", DESTRUCTIVE)));

        assertThat(panel.selectedTools()).extracting(McpToolDefinition::name)
                .containsExactlyInAnyOrder("read", "destroy");
    }

    @Test
    void defaultSelectionFallsBackToAnnotationsWhenNoStoredPreference() {
        ExtensionConfigStore store = stubbedConfigStore();
        panel.setSelectionPersistence(store, () -> "https://mcp.example.com/mcp");

        panel.populate(List.of(
                annotatedTool("read", READ_ONLY),
                annotatedTool("destroy", DESTRUCTIVE),
                annotatedTool("unknown", ToolAnnotations.EMPTY)));

        assertThat(panel.selectedTools()).extracting(McpToolDefinition::name)
                .containsExactly("read");
    }

    @Test
    void selectColumnRendererProducesPlainCheckBoxRegardlessOfAnnotations() {
        panel.populate(List.of(
                annotatedTool("read", READ_ONLY),
                annotatedTool("destroy", DESTRUCTIVE),
                annotatedTool("unknown", ToolAnnotations.EMPTY)));

        JTable table = panel.getTableForTest();
        TableCellRenderer renderer = table.getCellRenderer(0, SelectableInventoryTableModel.SELECT_COLUMN_INDEX);

        for (int row = 0; row < table.getRowCount(); row++) {
            Component component = renderer.getTableCellRendererComponent(
                    table, table.getValueAt(row, SelectableInventoryTableModel.SELECT_COLUMN_INDEX),
                    false, false, row, SelectableInventoryTableModel.SELECT_COLUMN_INDEX);
            assertThat(component).isInstanceOf(JCheckBox.class);
        }
    }

    @Test
    void annotationsColumnPaintsDestructiveLabelInRed() {
        panel.populate(List.of(annotatedTool("destroy", DESTRUCTIVE)));

        JLabel label = renderAnnotationsCell(0);

        assertThat(label.getText()).isEqualTo(ToolTableModel.LABEL_DESTRUCTIVE);
        assertThat(label.getForeground()).isNotEqualTo(Color.BLACK);
        assertThat(label.getForeground().getRed()).isGreaterThan(label.getForeground().getBlue());
        assertThat(label.getForeground().getRed()).isGreaterThan(label.getForeground().getGreen());
    }

    @Test
    void annotationsColumnUsesDefaultForegroundForReadOnly() {
        panel.populate(List.of(
                annotatedTool("read", READ_ONLY),
                annotatedTool("destroy", DESTRUCTIVE)));

        Color destructiveForeground = renderAnnotationsCell(1).getForeground();
        Color readForeground = renderAnnotationsCell(0).getForeground();

        assertThat(readForeground).isNotEqualTo(destructiveForeground);
        assertThat(readForeground).isEqualTo(panel.getTableForTest().getForeground());
    }

    @Test
    void detailNameLabelDisablesHtmlRendering() {
        panel.populate(List.of(annotatedTool("<html><b>x</b>", READ_ONLY)));

        panel.getTableForTest().setRowSelectionInterval(0, 0);

        assertThat(panel.getDetailPanelForTest().nameLabelForTest()
                .getClientProperty("html.disable")).isEqualTo(Boolean.TRUE);
    }

    @Test
    void selectingToolRendersInputSchemaIntoRawEditor() {
        McpToolDefinition tool = new McpToolDefinition("read", "desc",
                "{\"properties\":{\"path\":{\"type\":\"string\"},\"depth\":{\"type\":\"integer\"}}}");
        panel.populate(List.of(tool));

        panel.getTableForTest().setRowSelectionInterval(0, 0);

        ArgumentCaptor<ByteArray> captor = ArgumentCaptor.forClass(ByteArray.class);
        verify(parametersEditor, atLeastOnce()).setContents(captor.capture());
        assertThat(captor.getValue().toString())
                .contains("path")
                .contains("depth")
                .contains("integer");
    }

    @Test
    void nameColumnRendererDisablesHtmlRendering() {
        panel.populate(List.of(annotatedTool("<html><img src=http://x>", READ_ONLY)));

        Component component = renderNameCell(0);

        assertThat(((JComponent) component).getClientProperty("html.disable"))
                .isEqualTo(Boolean.TRUE);
    }

    @Test
    void annotationTooltipEscapesServerSuppliedTitle() {
        ToolAnnotations annotations = new ToolAnnotations("<html><img src=http://x>", true, null, null, null);

        String tooltip = ToolTableModel.annotationTooltip(annotations);

        assertThat(tooltip).doesNotStartWithIgnoringCase("<html>");
        assertThat(tooltip).doesNotContain("<html>");
        assertThat(tooltip).doesNotContain("<img");
        assertThat(tooltip).contains("&lt;html&gt;&lt;img src=http://x&gt;");
    }

    @Test
    void annotationTooltipNeverHtmlInterpretedEvenWhenServerValueLeads() {
        ToolAnnotations annotations = new ToolAnnotations("<html><b>x</b>", null, null, null, null);

        String tooltip = ToolTableModel.annotationTooltip(annotations);

        assertThat(tooltip.trim().toLowerCase()).doesNotStartWith("<html>");
        assertThat(tooltip).doesNotContain("<b>");
        assertThat(tooltip).contains("&lt;b&gt;");
    }

    private Component renderNameCell(int row) {
        JTable table = panel.getTableForTest();
        int column = SelectableInventoryTableModel.SELECT_COLUMN_INDEX + 1;
        TableCellRenderer renderer = table.getCellRenderer(row, column);
        return renderer.getTableCellRendererComponent(
                table, table.getValueAt(row, column), false, false, row, column);
    }

    private JLabel renderAnnotationsCell(int row) {
        JTable table = panel.getTableForTest();
        int column = ToolTableModel.COLUMN_ANNOTATIONS + 1;
        TableCellRenderer renderer = table.getColumnModel().getColumn(column).getCellRenderer();
        Object value = table.getValueAt(row, column);
        return (JLabel) renderer.getTableCellRendererComponent(
                table, value, false, false, row, column);
    }

    private List<McpToolDefinition> createTools(int count) {
        return java.util.stream.IntStream.range(0, count)
                .mapToObj(i -> new McpToolDefinition("tool-" + i, "Description " + i, "{}"))
                .toList();
    }

    private static McpToolDefinition annotatedTool(String name, ToolAnnotations annotations) {
        return new McpToolDefinition(name, "desc", "{}", List.of(), annotations);
    }

    private static ExtensionConfigStore stubbedConfigStore() {
        PersistedObject persistedStore = mock(PersistedObject.class);
        when(persistedStore.getBoolean(anyString())).thenReturn(null);
        Logging logging = mock(Logging.class);
        return new ExtensionConfigStore(persistedStore, logging);
    }
}
