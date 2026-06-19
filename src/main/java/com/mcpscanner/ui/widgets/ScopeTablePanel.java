package com.mcpscanner.ui.widgets;

import com.mcpscanner.config.ExtensionConfigStore.PersistedScope;

import javax.swing.AbstractCellEditor;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableCellEditor;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.EventObject;
import java.util.List;

public final class ScopeTablePanel extends JPanel {

    private static final String REMOVE_GLYPH = "×";
    private static final int REMOVE_COLUMN_MIN_WIDTH = 36;
    private static final int REMOVE_COLUMN_MAX_WIDTH = 48;
    private static final Insets REMOVE_BUTTON_MARGIN = new Insets(0, 6, 0, 6);
    private static final Dimension SCROLLABLE_VIEWPORT = new Dimension(400, 160);

    private final ScopeTableModel model;
    private final JTable table;
    private final JTextField addField;
    private final JButton addButton;

    public ScopeTablePanel() {
        super(new BorderLayout());
        this.model = new ScopeTableModel();
        this.table = new JTable(model);
        this.addField = new JTextField(20);
        this.addButton = new JButton("+");

        configureTable();
        add(buildScrollPane(), BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);
        setMinimumSize(new Dimension(0, 160));
    }

    private JScrollPane buildScrollPane() {
        JScrollPane scrollPane = new JScrollPane(table);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        return scrollPane;
    }

    public void replaceDiscovered(List<String> names) {
        model.replaceDiscovered(names);
    }

    public boolean removeDiscovered() {
        return model.removeDiscovered();
    }

    public List<String> enabledScopes() {
        return model.enabledScopes();
    }

    public void seed(List<PersistedScope> scopes) {
        model.seed(scopes);
    }

    public List<PersistedScope> snapshot() {
        return model.snapshot();
    }

    public List<PersistedScope> customScopesSnapshot() {
        return model.customScopesSnapshot();
    }

    public void setOnChange(Runnable callback) {
        TableModelListener listener = e -> callback.run();
        model.addTableModelListener(listener);
    }

    ScopeTableModel modelForTest() {
        return model;
    }

    private void configureTable() {
        table.setFillsViewportHeight(true);
        table.setPreferredScrollableViewportSize(SCROLLABLE_VIEWPORT);
        table.setEnabled(true);
        table.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        TableColumn removeCol = table.getColumnModel().getColumn(3);
        removeCol.setCellRenderer(new RemoveCellRenderer());
        removeCol.setCellEditor(new RemoveCellEditor());
        removeCol.setMinWidth(REMOVE_COLUMN_MIN_WIDTH);
        removeCol.setMaxWidth(REMOVE_COLUMN_MAX_WIDTH);
    }

    private static JButton createRemoveButton() {
        JButton button = new JButton(REMOVE_GLYPH);
        button.setMargin(REMOVE_BUTTON_MARGIN);
        button.setFocusPainted(false);
        button.setBorderPainted(true);
        button.setContentAreaFilled(true);
        return button;
    }

    private JPanel buildFooter() {
        JPanel footer = new JPanel(new FlowLayout(FlowLayout.LEFT));
        addField.putClientProperty("JTextField.placeholderText", "Add scope");
        addField.addActionListener(e -> onAdd());
        addField.addKeyListener(new BackspaceWatcher());
        addButton.addActionListener(e -> onAdd());
        footer.add(addField);
        footer.add(addButton);
        return footer;
    }

    private void onAdd() {
        String text = addField.getText().trim();
        if (!text.isEmpty()) {
            model.addCustomScope(text);
        }
        addField.setText("");
    }

    private final class BackspaceWatcher extends KeyAdapter {
        @Override
        public void keyPressed(KeyEvent evt) {
            if (evt.getKeyCode() == KeyEvent.VK_BACK_SPACE && addField.getText().isEmpty()) {
                model.removeLastCustomRow();
            }
        }
    }

    private final class RemoveCellRenderer implements TableCellRenderer {

        private final JButton button = createRemoveButton();
        private final JLabel emptyLabel = new JLabel("");

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                       boolean hasFocus, int row, int column) {
            if (!model.isCustomRow(row)) {
                return emptyLabel;
            }
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
            if (!model.isCustomRow(row)) {
                return emptyLabel;
            }
            button.setFont(table.getFont());
            return button;
        }

        private void handleRemoveClick(ActionEvent event) {
            if (currentRow >= 0 && currentRow < model.getRowCount() && model.isCustomRow(currentRow)) {
                model.removeRow(currentRow);
            }
            fireEditingStopped();
        }
    }
}
