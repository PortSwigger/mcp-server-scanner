package com.mcpscanner.ui.identities;

import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.ui.widgets.SwingHtmlGuard;
import com.mcpscanner.ui.widgets.ThemeColors;

import javax.swing.JCheckBox;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumn;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.MouseEvent;

final class IdentityTable extends JTable {

    private static final int ROW_HEIGHT = 22;
    private static final int HEADER_ALLOWANCE = 30;
    private static final int CELL_PADDING = 8;

    private final IdentityTableModel model;
    private final int[] contentWidths = new int[IdentityTableModel.COLUMN_COUNT];
    private int nameMinimum;

    IdentityTable(IdentityTableModel model) {
        super(model);
        this.model = model;
        setRowHeight(ROW_HEIGHT);
        setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        setFillsViewportHeight(true);
        setDefaultRenderer(String.class, new IdentityCellRenderer());
        setShowVerticalLines(false);
        setAutoResizeMode(AUTO_RESIZE_LAST_COLUMN);
        getTableHeader().setResizingAllowed(false);
        getTableHeader().setReorderingAllowed(false);
        installToggleColumns();
        fitColumns();
    }

    JScrollPane scrolled() {
        JScrollPane scroll = new JScrollPane(this);
        scroll.setColumnHeaderView(getTableHeader());
        fitHeight(scroll);
        return scroll;
    }

    void fitHeight(JScrollPane scroll) {
        Dimension fitted = new Dimension(0, HEADER_ALLOWANCE + ROW_HEIGHT * model.getRowCount());
        scroll.setPreferredSize(fitted);
        scroll.setMinimumSize(fitted);
        scroll.revalidate();
    }

    void fitColumns() {
        for (int column = 0; column < contentWidths.length; column++) {
            contentWidths[column] = contentWidth(column) + CELL_PADDING;
        }
        nameMinimum = headerWidth(IdentityTableModel.NAME) + CELL_PADDING;
        revalidate();
        getTableHeader().repaint();
    }

    @Override
    public void doLayout() {
        int fixed = contentWidths[IdentityTableModel.COMPARE] + contentWidths[IdentityTableModel.ACCESS]
                + contentWidths[IdentityTableModel.AUTH];
        int nameRoom = getWidth() - fixed - contentWidths[IdentityTableModel.STATUS];
        int name = Math.max(nameMinimum, Math.min(nameRoom, contentWidths[IdentityTableModel.NAME]));
        int[] widths = contentWidths.clone();
        widths[IdentityTableModel.NAME] = name;
        widths[IdentityTableModel.STATUS] = Math.max(0, getWidth() - fixed - name);
        for (int column = 0; column < widths.length; column++) {
            TableColumn sized = getColumnModel().getColumn(column);
            sized.setPreferredWidth(widths[column]);
            sized.setWidth(widths[column]);
        }
    }

    @Override
    protected JTableHeader createDefaultTableHeader() {
        return new JTableHeader(columnModel) {
            @Override
            public String getToolTipText(MouseEvent event) {
                int column = columnAtPoint(event.getPoint());
                return column >= 0 && convertColumnIndexToModel(column) == IdentityTableModel.ACCESS
                        ? model.accessHeading() : null;
            }
        };
    }

    private int headerWidth(int column) {
        return getTableHeader().getDefaultRenderer()
                .getTableCellRendererComponent(this, getColumnName(column), false, false, -1, column)
                .getPreferredSize().width;
    }

    private int contentWidth(int column) {
        int widest = headerWidth(column);
        for (int row = 0; row < getRowCount(); row++) {
            widest = Math.max(widest, prepareRenderer(getCellRenderer(row, column), row, column)
                    .getPreferredSize().width);
        }
        return widest;
    }

    private void installToggleColumns() {
        getColumnModel().getColumn(IdentityTableModel.COMPARE)
                .setCellRenderer(new ToggleCellRenderer(new JCheckBox(), this::anonymousNote));
    }

    private String anonymousNote(int row) {
        return model.rowAt(row).identity().isEmpty() ? Principal.ANONYMOUS_NAME + " is always compared" : null;
    }

    private final class IdentityCellRenderer extends DefaultTableCellRenderer {

        IdentityCellRenderer() {
            SwingHtmlGuard.disableHtml(this);
        }

        @Override
        public Component getTableCellRendererComponent(JTable table, Object value, boolean selected,
                                                       boolean focused, int row, int column) {
            super.getTableCellRendererComponent(table, value, selected, focused, row, column);
            setToolTipText(SwingHtmlGuard.escapeHtml(String.valueOf(value)));
            if (!selected) {
                setForeground(column == IdentityTableModel.STATUS ? statusColour(String.valueOf(value))
                        : table.getForeground());
            }
            return this;
        }

        private Color statusColour(String text) {
            if (text.startsWith(IdentityStatusText.READY_MARK)) {
                return ThemeColors.success();
            }
            return text.startsWith(IdentityStatusText.WARNING_MARK) ? ThemeColors.warning() : ThemeColors.muted();
        }
    }
}
