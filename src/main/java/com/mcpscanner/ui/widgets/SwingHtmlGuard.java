package com.mcpscanner.ui.widgets;

import javax.swing.JComponent;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

public final class SwingHtmlGuard {

    // Swing renders a label/renderer/tooltip value as HTML whenever it starts with "<html>".
    // Server-supplied strings are untrusted, so setting "html.disable" forces literal rendering
    // and prevents attacker markup (e.g. <img> beacons) from executing on the operator's host.
    public static <T extends JComponent> T disableHtml(T component) {
        component.putClientProperty("html.disable", Boolean.TRUE);
        return component;
    }

    // Installs an HTML-disabled default renderer for every String column so server-supplied
    // cell text is painted literally rather than interpreted as markup.
    public static void guardStringColumns(JTable table) {
        table.setDefaultRenderer(String.class, disableHtml(new DefaultTableCellRenderer()));
    }

    // "html.disable" is checked on the JToolTip Swing creates, not on the owning renderer, so it
    // cannot guard tooltip text. Escaping <, >, & guarantees the value can never start with "<html>"
    // (Swing's trigger for HTML rendering) nor smuggle a tag, regardless of how the tooltip is ordered.
    public static String escapeHtml(String text) {
        if (text == null) {
            return null;
        }
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");
    }

    private SwingHtmlGuard() {
    }
}
