package com.mcpscanner.ui.access;

import com.mcpscanner.access.AccessCell;
import com.mcpscanner.access.AccessRow;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.ui.widgets.SwingHtmlGuard;
import com.mcpscanner.ui.widgets.ThemeColors;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.Component;
import java.util.Optional;
import java.util.Set;

final class AccessCellRenderer extends DefaultTableCellRenderer {

    private static final Set<AccessOutcome> QUIET = Set.of(AccessOutcome.REFUSED, AccessOutcome.SKIPPED_WRITE,
            AccessOutcome.NOT_RUN);

    private final AccessTableModel model;

    AccessCellRenderer(AccessTableModel model) {
        this.model = model;
        SwingHtmlGuard.disableHtml(this);
    }

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean selected, boolean focused,
                                                   int row, int column) {
        AccessRow accessRow = (AccessRow) value;
        AccessColumn accessColumn = model.columnAt(table.convertColumnIndexToModel(column));
        String text = text(accessRow, accessColumn);
        super.getTableCellRendererComponent(table, text, selected, focused, row, column);
        setToolTipText(SwingHtmlGuard.escapeHtml(tooltip(text, cell(accessRow, accessColumn))));
        if (!selected) {
            paintUnselected(table, cell(accessRow, accessColumn));
        }
        return this;
    }

    private void paintUnselected(JTable table, Optional<AccessCell> cell) {
        if (cell.filter(AccessCell::anomaly).isPresent()) {
            setBackground(AnomalyColors.background(table.getBackground()));
            setForeground(AnomalyColors.foreground(getBackground()));
            return;
        }
        setBackground(table.getBackground());
        setForeground(cell.flatMap(AccessCell::outcome).filter(QUIET::contains).isPresent()
                || cell.filter(value -> !value.checked()).isPresent() ? ThemeColors.muted() : table.getForeground());
    }

    static String text(AccessRow row, AccessColumn column) {
        if (column instanceof AccessColumn.Identity identity) {
            return AccessCellText.identity(row, identity.principal());
        }
        if (column instanceof AccessColumn.Anonymous) {
            return AccessCellText.anonymous(row.anonymous());
        }
        return column instanceof AccessColumn.Item ? AccessCellText.item(row.item()) : AccessCellText.expectation(row);
    }

    static String tooltip(String text, Optional<AccessCell> cell) {
        return cell.flatMap(AccessCell::notComparedReason).map(reason -> text + ": " + reason).orElse(text);
    }

    private static Optional<AccessCell> cell(AccessRow row, AccessColumn column) {
        if (column instanceof AccessColumn.Identity identity) {
            return Optional.of(row.cell(identity.principal().id()));
        }
        return column instanceof AccessColumn.Anonymous ? Optional.of(row.anonymous()) : Optional.empty();
    }
}
