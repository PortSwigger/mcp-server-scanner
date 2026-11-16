package com.mcpscanner.ui.access;

import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.ui.widgets.SwingHtmlGuard;

import javax.swing.DefaultListCellRenderer;
import javax.swing.JList;
import java.awt.Component;

final class ExpectationChoiceRenderer extends DefaultListCellRenderer {

    private String owner = "";

    void showOwner(String owner) {
        this.owner = owner;
    }

    @Override
    public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected,
                                                  boolean focused) {
        if (!(value instanceof AccessExpectation expectation)) {
            return super.getListCellRendererComponent(list, value, index, selected, focused);
        }
        super.getListCellRendererComponent(list, ExpectationText.label(expectation, owner), index, selected, focused);
        setToolTipText(SwingHtmlGuard.escapeHtml(ExpectationText.tooltip(expectation, owner)));
        return this;
    }
}
