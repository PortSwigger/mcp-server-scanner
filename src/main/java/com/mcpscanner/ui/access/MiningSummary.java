package com.mcpscanner.ui.access;

import com.mcpscanner.ui.widgets.SwingHtmlGuard;
import com.mcpscanner.ui.widgets.WrappingText;

import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JComponent;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import java.util.ArrayList;
import java.util.List;

final class MiningSummary {

    static final String LIVE_SERVER_WARNING = "Collecting IDs calls the server's tools as every configured user and "
            + "Anonymous, gathers the IDs in the replies and feeds those real IDs back into the tools. Run it only "
            + "against a server you may test.";
    static final String OTHER_CALLS = "resource reads, resources/list and prompts";
    static final int TEXT_WIDTH = 440;
    private static final int GAP = 8;
    private static final int MAX_VISIBLE_TOOLS = 10;

    private MiningSummary() {
    }

    static JPanel withLead(String lead, ToolsToCall tools) {
        List<JComponent> stacked = new ArrayList<>();
        stacked.add(wrapped(lead));
        stacked.addAll(parts(tools));
        return stack(stacked);
    }

    static JPanel of(ToolsToCall tools) {
        return stack(parts(tools));
    }

    static String countText(ToolsToCall tools) {
        if (tools.isEmpty()) {
            return "No tools will be called, only " + OTHER_CALLS + ".";
        }
        int count = tools.names().size();
        String writes = tools.writes() ? " (" + tools.mayWrite().size() + " may write)" : "";
        return count + (count == 1 ? " tool" : " tools") + writes + " will be called, besides " + OTHER_CALLS + ":";
    }

    private static List<JComponent> parts(ToolsToCall tools) {
        List<JComponent> parts = new ArrayList<>();
        if (tools.writes()) {
            parts.add(wrapped(LIVE_SERVER_WARNING));
        }
        parts.add(wrapped(countText(tools)));
        if (!tools.isEmpty()) {
            parts.add(toolList(tools));
        }
        return parts;
    }

    private static JPanel stack(List<JComponent> parts) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        for (JComponent part : parts) {
            if (panel.getComponentCount() > 0) {
                panel.add(Box.createVerticalStrut(GAP));
            }
            part.setAlignmentX(JComponent.LEFT_ALIGNMENT);
            panel.add(part);
        }
        return panel;
    }

    private static WrappingText wrapped(String text) {
        return new WrappingText(text).fixedWidth(TEXT_WIDTH);
    }

    private static JScrollPane toolList(ToolsToCall tools) {
        JList<String> list = new JList<>(tools.names().toArray(String[]::new));
        list.setCellRenderer(SwingHtmlGuard.disableHtml(new DefaultListCellRenderer()));
        list.setVisibleRowCount(Math.min(MAX_VISIBLE_TOOLS, tools.names().size()));
        return new JScrollPane(list);
    }
}
