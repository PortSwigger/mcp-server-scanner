package com.mcpscanner.ui;

import com.mcpscanner.auth.oauth.ScopeSelection;
import com.mcpscanner.config.ExtensionConfigStore.PersistedScope;

import javax.swing.BorderFactory;
import com.mcpscanner.ui.widgets.Contrast;
import com.mcpscanner.ui.widgets.FadedWhenDisabled;
import javax.swing.JButton;
import javax.swing.UIManager;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.event.TableModelListener;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.List;

public final class ScopeTablePanel extends JPanel {

    private static final Dimension SCROLLABLE_VIEWPORT = new Dimension(400, 160);
    private static final int ENABLED_WIDTH = 64;
    private static final int SOURCE_WIDTH = 90;

    private final ScopeTableModel model;
    private final JTable table;
    private final JTextField addField;
    private final JButton addButton;
    private final JButton removeButton = new JButton("−");
    private static final double LOCKED_FADE = 0.55;

    private boolean locked;

    public ScopeTablePanel() {
        super(new BorderLayout());
        this.model = new ScopeTableModel();
        this.table = new JTable(model) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return !locked && super.isCellEditable(row, column);
            }

            @Override
            public java.awt.Component prepareRenderer(javax.swing.table.TableCellRenderer renderer, int row,
                                                      int column) {
                java.awt.Component cell = super.prepareRenderer(renderer, row, column);
                cell.setEnabled(!locked);
                return cell;
            }
        };
        this.addField = FadedWhenDisabled.install(new JTextField(20));
        this.addButton = FadedWhenDisabled.install(new JButton("+"));
        FadedWhenDisabled.install(removeButton);
        this.addButton.setToolTipText("Add scope");
        this.addButton.getAccessibleContext().setAccessibleName("Add scope");
        this.addField.getAccessibleContext().setAccessibleName("New scope");

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

    public ScopeSelection scopeSelection() {
        return model.scopeSelection();
    }

    public void seed(List<PersistedScope> scopes) {
        model.seed(scopes);
    }

    public List<PersistedScope> scopesSnapshot() {
        return model.scopesSnapshot();
    }

    public void setOnChange(Runnable callback) {
        TableModelListener listener = e -> callback.run();
        model.addTableModelListener(listener);
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
        if (locked && table.isEditing()) {
            table.getCellEditor().cancelCellEditing();
        }
        table.setEnabled(!locked);
        table.setForeground(locked ? Contrast.blend(UIManager.getColor("Table.foreground"), table.getBackground(),
                LOCKED_FADE) : UIManager.getColor("Table.foreground"));
        addField.setEnabled(!locked);
        addButton.setEnabled(!locked);
        refreshRemoveButton();
    }

    private void configureTable() {
        table.setFillsViewportHeight(true);
        table.setPreferredScrollableViewportSize(SCROLLABLE_VIEWPORT);
        table.setEnabled(true);
        table.putClientProperty("terminateEditOnFocusLost", Boolean.TRUE);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        fixWidth(ScopeTableModel.COLUMN_ENABLED, ENABLED_WIDTH);
        fixWidth(ScopeTableModel.COLUMN_SOURCE, SOURCE_WIDTH);
        table.getSelectionModel().addListSelectionListener(event -> refreshRemoveButton());
        model.addTableModelListener(event -> refreshRemoveButton());
    }

    private void fixWidth(int column, int width) {
        table.getColumnModel().getColumn(column).setPreferredWidth(width);
        table.getColumnModel().getColumn(column).setMaxWidth(width);
    }

    private void refreshRemoveButton() {
        int row = table.getSelectedRow();
        removeButton.setEnabled(!locked && row >= 0 && row < model.getRowCount() && model.isCustomRow(row));
    }

    private void removeSelected() {
        int row = table.getSelectedRow();
        if (row >= 0 && model.isCustomRow(row)) {
            model.removeRow(row);
        }
    }

    JTable table() {
        return table;
    }

    JButton removeButton() {
        return removeButton;
    }

    private JPanel buildFooter() {
        JPanel footer = new JPanel(new BorderLayout(8, 0));
        footer.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
        addField.putClientProperty("JTextField.placeholderText", "Add scope");
        addField.addActionListener(e -> onAdd());
        addField.addKeyListener(new BackspaceWatcher());
        addButton.addActionListener(e -> onAdd());
        removeButton.setToolTipText("Remove the selected custom scope");
        removeButton.getAccessibleContext().setAccessibleName("Remove scope");
        removeButton.addActionListener(e -> removeSelected());
        refreshRemoveButton();
        JPanel buttons = new JPanel(new GridLayout(1, 2, 4, 0));
        buttons.add(addButton);
        buttons.add(removeButton);
        footer.add(addField, BorderLayout.CENTER);
        footer.add(buttons, BorderLayout.EAST);
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
}
