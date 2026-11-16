package com.mcpscanner.ui.access;

import com.mcpscanner.access.AccessRow;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.ui.widgets.SwingHtmlGuard;

import javax.swing.DefaultCellEditor;
import javax.swing.JComboBox;
import javax.swing.JTable;
import java.awt.Component;

final class ExpectationCellEditor extends DefaultCellEditor {

    private final JComboBox<AccessExpectation> choices;
    private final ExpectationChoiceRenderer renderer = new ExpectationChoiceRenderer();

    ExpectationCellEditor() {
        this(new JComboBox<>(AccessExpectation.values()));
    }

    private ExpectationCellEditor(JComboBox<AccessExpectation> choices) {
        super(choices);
        this.choices = choices;
        choices.setRenderer(SwingHtmlGuard.disableHtml(renderer));
    }

    @Override
    public Component getTableCellEditorComponent(JTable table, Object value, boolean selected, int row, int column) {
        super.getTableCellEditorComponent(table, value, selected, row, column);
        AccessRow accessRow = (AccessRow) value;
        renderer.showOwner(accessRow.owner().name());
        choices.setSelectedItem(accessRow.expectation());
        return choices;
    }

    @Override
    public Object getCellEditorValue() {
        return choices.getSelectedItem();
    }
}
