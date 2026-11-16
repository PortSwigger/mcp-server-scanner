package com.mcpscanner.ui.access;

import com.mcpscanner.access.AccessRow;
import com.mcpscanner.access.AccessSnapshot;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.ui.widgets.DetailText;
import com.mcpscanner.ui.widgets.ThemeColors;
import com.mcpscanner.ui.widgets.WholeRowScrollPane;

import javax.swing.BorderFactory;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Optional;
import java.util.Set;

final class AccessMatrixView extends JPanel {

    private static final int ROW_HEIGHT = 24;
    private static final int ITEM_WIDTH = 230;
    private static final int CELL_WIDTH = 170;

    private final AccessTableModel model;
    private final JTable table;
    private final AccessToolbar toolbar;
    private final CheckAccessControl checkAccess;
    private final AccessRowMenu rowMenu;
    private final JLabel info = new JLabel();
    private final DetailText detail = DetailText.prose();
    private AccessSnapshot snapshot = new AccessSnapshot(false, java.util.List.of(), java.util.List.of());
    private Set<String> usersWithoutIds = Set.of();

    AccessMatrixView(AccessTableModel model, CheckAccessControl checkAccess, AccessRowMenu rowMenu,
                     Runnable refreshListings) {
        super(new BorderLayout());
        this.model = model;
        this.checkAccess = checkAccess;
        this.rowMenu = rowMenu;
        this.table = new JTable(model);
        table.setTableHeader(new NotedHeader(table.getColumnModel()));
        this.toolbar = new AccessToolbar(checkAccess, refreshListings, this::refilter);
        configureTable();
        add(north(), BorderLayout.NORTH);
        add(new WholeRowScrollPane(table), BorderLayout.CENTER);
        add(detailPane(), BorderLayout.SOUTH);
    }

    JTable table() {
        return table;
    }

    AccessToolbar toolbar() {
        return toolbar;
    }

    JLabel info() {
        return info;
    }

    DetailText detail() {
        return detail;
    }

    void show(AccessSnapshot next, Set<String> withoutIds) {
        Optional<AccessItemKey> selectedItem = selectedRow().map(row -> row.item().key());
        int selectedColumn = table.getSelectedColumn();
        snapshot = next;
        usersWithoutIds = Set.copyOf(withoutIds);
        if (!table.isEditing()) {
            model.show(next.principals(), next.rows(toolbar.filter()), usersWithoutIds);
            sizeColumns();
            restoreSelection(selectedItem, selectedColumn);
        }
        checkAccess.show(next, next.rows());
        toolbar.enableRefresh(next.connected());
        showInfo();
        showDetail();
    }

    private void refilter() {
        show(snapshot, usersWithoutIds);
    }

    private void configureTable() {
        table.setRowHeight(ROW_HEIGHT);
        table.setCellSelectionEnabled(true);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setDefaultRenderer(AccessRow.class, new AccessCellRenderer(model));
        ExpectationCellEditor expectationEditor = new ExpectationCellEditor();
        expectationEditor.addCellEditorListener(new DeferredRefresh());
        table.setDefaultEditor(AccessRow.class, expectationEditor);
        table.getSelectionModel().addListSelectionListener(event -> showDetail());
        table.getColumnModel().getSelectionModel().addListSelectionListener(event -> showDetail());
        table.addMouseListener(new PopupTrigger());
        table.addMouseListener(new ExpectationShortcut());
    }

    boolean openExpectationFrom(int viewRow, int viewColumn) {
        if (viewRow < 0 || viewColumn < 0 || !unconfirmedSameResultAt(viewRow, viewColumn)) {
            return false;
        }
        boolean editing = table.editCellAt(viewRow, table.convertColumnIndexToView(model.expectationColumn()));
        if (editing && table.getEditorComponent() instanceof JComboBox<?> choices && choices.isShowing()) {
            choices.requestFocusInWindow();
            choices.showPopup();
        }
        return editing;
    }

    private boolean unconfirmedSameResultAt(int viewRow, int viewColumn) {
        AccessRow row = model.rowAt(table.convertRowIndexToModel(viewRow));
        return model.columnAt(table.convertColumnIndexToModel(viewColumn)) instanceof AccessColumn.Identity identity
                && row.unconfirmedSameResult(identity.principal());
    }

    private void sizeColumns() {
        for (int index = 0; index < table.getColumnCount(); index++) {
            TableColumn column = table.getColumnModel().getColumn(index);
            column.setPreferredWidth(index == 0 ? ITEM_WIDTH : CELL_WIDTH);
        }
    }

    private JPanel north() {
        info.setForeground(ThemeColors.muted());
        info.setBorder(BorderFactory.createEmptyBorder(2, 10, 4, 10));
        JPanel north = new JPanel(new BorderLayout());
        north.add(toolbar, BorderLayout.NORTH);
        north.add(info, BorderLayout.SOUTH);
        return north;
    }

    private JPanel detailPane() {
        detail.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, ThemeColors.separator()),
                BorderFactory.createEmptyBorder(8, 10, 8, 10)));
        detail.area().setOpaque(false);
        JPanel pane = new JPanel(new BorderLayout());
        pane.add(detail, BorderLayout.CENTER);
        return pane;
    }

    private void showInfo() {
        Optional<String> text = AccessInfoNote.of(snapshot);
        info.setText(text.orElse(""));
        info.setVisible(text.isPresent());
    }

    private void showDetail() {
        detail.show(selectedRow().map(row -> AccessDetailText.describe(row, selectedColumn())).orElse(""));
        revalidate();
    }

    private Optional<AccessRow> selectedRow() {
        int row = table.getSelectedRow();
        return row < 0 || row >= model.getRowCount() ? Optional.empty()
                : Optional.of(model.rowAt(table.convertRowIndexToModel(row)));
    }

    private AccessColumn selectedColumn() {
        int column = table.getSelectedColumn();
        return column < 0 ? new AccessColumn.Item() : model.columnAt(table.convertColumnIndexToModel(column));
    }

    private void restoreSelection(Optional<AccessItemKey> item, int column) {
        item.ifPresent(key -> {
            for (int index = 0; index < model.getRowCount(); index++) {
                if (model.rowAt(index).item().key().equals(key)) {
                    table.changeSelection(index, Math.max(0, Math.min(column, table.getColumnCount() - 1)),
                            false, false);
                    return;
                }
            }
        });
    }

    private final class NotedHeader extends JTableHeader {

        NotedHeader(TableColumnModel columns) {
            super(columns);
        }

        @Override
        public String getToolTipText(MouseEvent event) {
            int column = columnAtPoint(event.getPoint());
            return column < 0 ? null
                    : model.columnAt(table.convertColumnIndexToModel(column)).note().orElse(null);
        }
    }

    private final class DeferredRefresh implements CellEditorListener {
        @Override
        public void editingStopped(ChangeEvent event) {
            SwingUtilities.invokeLater(AccessMatrixView.this::refilter);
        }

        @Override
        public void editingCanceled(ChangeEvent event) {
            SwingUtilities.invokeLater(AccessMatrixView.this::refilter);
        }
    }

    private final class ExpectationShortcut extends MouseAdapter {
        @Override
        public void mouseClicked(MouseEvent event) {
            if (event.getClickCount() == 2) {
                openExpectationFrom(table.rowAtPoint(event.getPoint()), table.columnAtPoint(event.getPoint()));
            }
        }
    }

    private final class PopupTrigger extends MouseAdapter {
        @Override
        public void mousePressed(MouseEvent event) {
            showIfPopup(event);
        }

        @Override
        public void mouseReleased(MouseEvent event) {
            showIfPopup(event);
        }

        private void showIfPopup(MouseEvent event) {
            int row = table.rowAtPoint(event.getPoint());
            int column = table.columnAtPoint(event.getPoint());
            if (!event.isPopupTrigger() || row < 0) {
                return;
            }
            table.changeSelection(row, Math.max(column, 0), false, false);
            JPopupMenu menu = rowMenu.menuFor(snapshot, model.rowAt(table.convertRowIndexToModel(row)),
                    principalAt(column));
            menu.show(table, event.getX(), event.getY());
        }

        private Optional<Principal> principalAt(int column) {
            return column < 0 ? Optional.empty()
                    : Optional.of(model.columnAt(table.convertColumnIndexToModel(column)))
                    .filter(AccessColumn.Identity.class::isInstance)
                    .map(identity -> ((AccessColumn.Identity) identity).principal());
        }
    }
}
