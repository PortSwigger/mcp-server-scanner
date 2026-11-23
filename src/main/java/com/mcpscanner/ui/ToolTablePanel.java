package com.mcpscanner.ui;

import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.mcp.McpMethods;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ToolAnnotations;
import com.mcpscanner.ui.widgets.ThemeColors;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import java.awt.Component;
import java.util.List;
import java.util.function.Supplier;

import static com.mcpscanner.ui.SelectableInventoryTableModel.SELECT_COLUMN_INDEX;

public class ToolTablePanel extends AbstractInventoryTablePanel<McpToolDefinition, ToolDetailPanel> {

    private static final int SELECT_COLUMN_WIDTH = 56;
    private static final int ANNOTATIONS_COLUMN_WIDTH = 130;
    private static final int ANNOTATIONS_MIN_WIDTH = 110;
    private static final int NAME_COLUMN_WIDTH = 200;
    private static final int DESCRIPTION_COLUMN_WIDTH = 600;

    private final InventoryTicks ticks;
    private ToolSelectionPreferences preferences = ToolSelectionPreferences.none();
    private boolean suppressPersistence;

    public ToolTablePanel() {
        this(InventoryTicks.SCAN_SELECTION);
    }

    ToolTablePanel(InventoryTicks ticks) {
        this(ticks, ticks.shown() ? List.of(new JButton("Select read-only")) : List.of());
    }

    private ToolTablePanel(InventoryTicks ticks, List<JButton> selectReadOnlyButton) {
        super(ticks, List.<JComponent>copyOf(selectReadOnlyButton));
        this.ticks = ticks;
        configureColumns();
        selectReadOnlyButton.forEach(this::installToolbarActions);
        if (ticks.shown()) {
            getTableModel().addTableModelListener(this::onTableModelChange);
            view().disableSorting(SELECT_COLUMN_INDEX);
        }
    }

    @Override
    protected SelectableInventoryTableModel<McpToolDefinition> createTableModel() {
        return new ToolTableModel();
    }

    @Override
    protected ToolDetailPanel createDetailPanel(InventoryTicks ticks) {
        return new ToolDetailPanel(ticks);
    }

    @Override
    protected String itemNoun() {
        return "tool";
    }

    @Override
    protected String listMethod() {
        return McpMethods.TOOLS_LIST;
    }

    @Override
    protected void onPopulated(List<McpToolDefinition> tools) {
        if (!preferences.isConfigured()) {
            return;
        }
        suppressPersistence = true;
        try {
            for (int row = 0; row < tools.size(); row++) {
                setTicked(row, preferences.defaultSelection(tools.get(row)));
            }
        } finally {
            suppressPersistence = false;
        }
    }

    public List<McpToolDefinition> selectedTools() {
        return getTableModel().selectedItems();
    }

    public void setSelectionPersistence(ExtensionConfigStore configStore, Supplier<String> endpointSupplier) {
        if (ticks.shown()) {
            this.preferences = new ToolSelectionPreferences(configStore, endpointSupplier);
        }
    }

    private void configureSelectColumn() {
        TableColumn selectColumn = column(SELECT_COLUMN_INDEX);
        selectColumn.setMaxWidth(SELECT_COLUMN_WIDTH);
        selectColumn.setMinWidth(SELECT_COLUMN_WIDTH);
        selectColumn.setCellRenderer(new SelectCellRenderer());
    }

    private void configureColumns() {
        if (ticks.shown()) {
            configureSelectColumn();
        }
        column(ToolTableModel.COLUMN_NAME + 1).setPreferredWidth(NAME_COLUMN_WIDTH);
        column(ToolTableModel.COLUMN_DESCRIPTION + 1).setPreferredWidth(DESCRIPTION_COLUMN_WIDTH);
        TableColumn annotationsColumn = column(ToolTableModel.COLUMN_ANNOTATIONS + 1);
        annotationsColumn.setPreferredWidth(ANNOTATIONS_COLUMN_WIDTH);
        annotationsColumn.setMinWidth(ANNOTATIONS_MIN_WIDTH);
        annotationsColumn.setMaxWidth(ANNOTATIONS_COLUMN_WIDTH);
        annotationsColumn.setCellRenderer(new AnnotationsCellRenderer());
    }

    private TableColumn column(int modelIndex) {
        return table().getColumnModel().getColumn(table().convertColumnIndexToView(modelIndex));
    }

    private void installToolbarActions(JButton selectReadOnlyButton) {
        selectReadOnlyButton.setToolTipText("Tick only the tools the server annotates as read-only");
        selectReadOnlyButton.addActionListener(e -> applyReadOnlyPreset());
    }

    private void onTableModelChange(TableModelEvent event) {
        if (event.getType() == TableModelEvent.UPDATE && event.getColumn() == SELECT_COLUMN_INDEX) {
            persistSelectionChange(event.getFirstRow());
        }
    }

    private void persistSelectionChange(int row) {
        McpToolDefinition tool = getTableModel().rowAt(row);
        if (!suppressPersistence && tool != null) {
            preferences.remember(tool, getTableModel().isSelected(row));
        }
    }

    private void applyReadOnlyPreset() {
        for (int row = 0; row < getTableModel().getRowCount(); row++) {
            McpToolDefinition tool = getTableModel().rowAt(row);
            if (tool != null) {
                setTicked(row, tool.annotations().isExplicitlyReadOnly());
            }
        }
    }

    private void setTicked(int row, boolean ticked) {
        getTableModel().setValueAt(ticked, row, SELECT_COLUMN_INDEX);
    }

    private static ToolAnnotations annotationsAt(JTable table, int viewRow) {
        if (!(table.getModel() instanceof ToolTableModel model)) {
            return null;
        }
        McpToolDefinition tool = model.rowAt(table.convertRowIndexToModel(viewRow));
        return tool != null ? tool.annotations() : null;
    }

    private static String annotationTooltipAt(JTable table, int viewRow) {
        ToolAnnotations annotations = annotationsAt(table, viewRow);
        return annotations != null ? ToolTableModel.annotationTooltip(annotations) : null;
    }

    private static final class SelectCellRenderer implements TableCellRenderer {
        private final JCheckBox checkBox = new JCheckBox();

        SelectCellRenderer() {
            checkBox.setHorizontalAlignment(SwingConstants.CENTER);
            checkBox.setOpaque(true);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            checkBox.setSelected(Boolean.TRUE.equals(value));
            checkBox.setEnabled(TickableCellRenderer.isTickable(table, row, column));
            checkBox.setBackground(isSelected ? table.getSelectionBackground() : table.getBackground());
            checkBox.setForeground(isSelected ? table.getSelectionForeground() : table.getForeground());
            checkBox.setToolTipText(annotationTooltipAt(table, row));
            return checkBox;
        }
    }

    private static final class AnnotationsCellRenderer extends DefaultTableCellRenderer {

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                                                       boolean isSelected, boolean hasFocus,
                                                       int row, int column) {
            JLabel label = (JLabel) super.getTableCellRendererComponent(
                    table, value, isSelected, hasFocus, row, column);
            label.setToolTipText(annotationTooltipAt(table, row));
            if (!isSelected) {
                label.setForeground(ToolTableModel.LABEL_DESTRUCTIVE.equals(value)
                        ? ThemeColors.error() : table.getForeground());
            }
            return label;
        }
    }
}
