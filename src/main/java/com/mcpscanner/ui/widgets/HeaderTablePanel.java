package com.mcpscanner.ui.widgets;

import javax.swing.AbstractCellEditor;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.util.EventObject;
import java.util.Map;

public final class HeaderTablePanel extends JPanel {

    private static final String REMOVE_GLYPH = "×";
    private static final int REMOVE_COLUMN_MIN_WIDTH = 36;
    private static final int REMOVE_COLUMN_MAX_WIDTH = 48;
    private static final Insets REMOVE_BUTTON_MARGIN = new Insets(0, 6, 0, 6);
    private static final Dimension SCROLLABLE_VIEWPORT = new Dimension(400, 120);
    private static final int REMOVE_COLUMN = 2;

    private final HeaderTableModel model;
    private final JTable table;
    private final JButton addButton;

    public HeaderTablePanel() {
        super(new BorderLayout());
        this.model = new HeaderTableModel();
        this.table = new JTable(model);
        this.addButton = new JButton("+");

        configureTable();
        add(new JScrollPane(table), BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);
    }

    public Map<String, String> headers() {
        return model.headers();
    }

    public void setHeaders(Map<String, String> headers) {
        model.setHeaders(headers);
    }

    HeaderTableModel modelForTest() {
        return model;
    }

    private void configureTable() {
        table.setFillsViewportHeight(true);
        table.setPreferredScrollableViewportSize(SCROLLABLE_VIEWPORT);
        table.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        TableColumn removeCol = table.getColumnModel().getColumn(REMOVE_COLUMN);
        removeCol.setCellRenderer(new RemoveCellRenderer());
        removeCol.setCellEditor(new RemoveCellEditor());
        removeCol.setMinWidth(REMOVE_COLUMN_MIN_WIDTH);
        removeCol.setMaxWidth(REMOVE_COLUMN_MAX_WIDTH);
    }

    private JPanel buildFooter() {
        JPanel footer = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addButton.addActionListener(e -> model.addRow());
        footer.add(addButton);
        return footer;
    }

    private static JButton createRemoveButton() {
        JButton button = new JButton(REMOVE_GLYPH);
        button.setMargin(REMOVE_BUTTON_MARGIN);
        button.setFocusPainted(false);
        button.setBorderPainted(true);
        button.setContentAreaFilled(true);
        return button;
    }

    private final class RemoveCellRenderer implements TableCellRenderer {

        private final JButton button = createRemoveButton();

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            button.setFont(table.getFont());
            return button;
        }
    }

    private final class RemoveCellEditor extends AbstractCellEditor implements TableCellEditor {

        private final JButton button = createRemoveButton();
        private final JLabel emptyLabel = new JLabel("");
        private int currentRow = -1;

        RemoveCellEditor() {
            button.addActionListener(this::handleRemoveClick);
        }

        @Override
        public Object getCellEditorValue() {
            return "";
        }

        @Override
        public boolean isCellEditable(EventObject anEvent) {
            return true;
        }

        @Override
        public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected,
                                                     int row, int column) {
            currentRow = row;
            button.setFont(table.getFont());
            return button;
        }

        private void handleRemoveClick(ActionEvent event) {
            if (currentRow >= 0 && currentRow < model.getRowCount()) {
                model.removeRow(currentRow);
            }
            fireEditingStopped();
        }
    }
}
