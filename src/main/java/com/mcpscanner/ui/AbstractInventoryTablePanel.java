package com.mcpscanner.ui;

import com.mcpscanner.ui.widgets.SwingHtmlGuard;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import java.awt.BorderLayout;
import java.util.List;

public abstract class AbstractInventoryTablePanel<T> extends JPanel {

    private final InventoryTableModel<T> model;
    private final JTable table;
    private final InventoryDetailPanel<T> detail;

    private static final int SELECT_COLUMN_WIDTH = 60;

    protected AbstractInventoryTablePanel() {
        super(new BorderLayout());
        this.model = createTableModel();
        this.table = new JTable(model);
        this.table.setAutoCreateRowSorter(true);
        this.detail = createDetailPanel();

        narrowSelectColumnIfPresent();
        SwingHtmlGuard.guardStringColumns(table);
        table.getSelectionModel().addListSelectionListener(this::onSelectionChanged);

        add(buildSplitPane(), BorderLayout.CENTER);
    }

    private void narrowSelectColumnIfPresent() {
        if (model instanceof SelectableInventoryTableModel<?>) {
            table.getColumnModel().getColumn(SelectableInventoryTableModel.SELECT_COLUMN_INDEX)
                    .setMaxWidth(SELECT_COLUMN_WIDTH);
        }
    }

    protected abstract InventoryTableModel<T> createTableModel();

    protected abstract InventoryDetailPanel<T> createDetailPanel();

    public final void populate(List<T> items) {
        model.populate(items);
        detail.clear();
    }

    InventoryTableModel<T> getTableModel() {
        return model;
    }

    JTable getTableForTest() {
        return table;
    }

    InventoryDetailPanel<T> getDetailPanelForTest() {
        return detail;
    }

    protected static String safeText(String value) {
        return value != null ? value : "";
    }

    private JSplitPane buildSplitPane() {
        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table),
                detail.component());
        split.setResizeWeight(0.6);
        return split;
    }

    private void onSelectionChanged(ListSelectionEvent event) {
        if (event.getValueIsAdjusting()) {
            return;
        }
        updateDetail();
    }

    private void updateDetail() {
        ListSelectionModel selection = table.getSelectionModel();
        if (selection.isSelectionEmpty()
                || selection.getMinSelectionIndex() != selection.getMaxSelectionIndex()) {
            detail.clear();
            return;
        }
        int viewRow = selection.getMinSelectionIndex();
        int modelRow = table.convertRowIndexToModel(viewRow);
        T item = model.rowAt(modelRow);
        detail.show(item);
    }
}
