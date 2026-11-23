package com.mcpscanner.ui;

import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.logging.RetainedLogEntries;
import com.mcpscanner.logging.RetainedLogEntries.Eviction;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.function.Consumer;

public final class LoggerPanel extends JPanel {

    private static final int AUTO_SCROLL_THRESHOLD_PX = 2;
    private static final int MAX_ENTRIES = 1000;

    private final HangingIndentLog textArea = new HangingIndentLog(LogLine.PREFIX_COLUMNS);
    private final JScrollPane scrollPane;
    private final RetainedLogEntries entries = new RetainedLogEntries(MAX_ENTRIES);
    private final JComboBox<LogLevelFilter> levelFilter = new JComboBox<>(LogLevelFilter.values());
    private final JButton clearButton = new JButton("Clear");
    private final McpEventLog eventLog;
    private final Consumer<McpEventLog.LogEntry> logListener = this::onEntry;

    public LoggerPanel(McpEventLog eventLog) {
        super(new BorderLayout());
        this.eventLog = eventLog;

        this.scrollPane = new JScrollPane(textArea,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        add(scrollPane, BorderLayout.CENTER);
        add(buildFooter(), BorderLayout.SOUTH);

        eventLog.subscribe(logListener).forEach(entries::add);
        levelFilter.addActionListener(event -> rerender());
        rerender();
    }

    public void dispose() {
        eventLog.unsubscribe(logListener);
    }

    private JPanel buildFooter() {
        JPanel footer = new JPanel(new BorderLayout());
        footer.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        footer.add(buildButtonRow(), BorderLayout.NORTH);
        return footer;
    }

    private JPanel buildButtonRow() {
        JPanel row = new JPanel();
        row.setLayout(new BoxLayout(row, BoxLayout.LINE_AXIS));

        JButton copyButton = new JButton("Copy all");
        copyButton.addActionListener(e -> copyAll());

        clearButton.addActionListener(e -> clear());
        levelFilter.setToolTipText("Show only entries of this level");
        levelFilter.setMaximumSize(levelFilter.getPreferredSize());
        JLabel showLabel = new JLabel("Show:");
        showLabel.setLabelFor(levelFilter);

        row.add(showLabel);
        row.add(Box.createHorizontalStrut(4));
        row.add(levelFilter);
        row.add(Box.createHorizontalStrut(8));
        row.add(copyButton);
        row.add(Box.createHorizontalStrut(8));
        row.add(clearButton);
        row.add(Box.createHorizontalGlue());
        return row;
    }

    private void onEntry(McpEventLog.LogEntry entry) {
        SwingUtilities.invokeLater(() -> appendOnEdt(entry));
    }

    private void appendOnEdt(McpEventLog.LogEntry entry) {
        LogLevelFilter filter = selectedFilter();
        entries.add(entry).ifPresent(eviction -> forgetLine(eviction, filter));
        if (!filter.accepts(entry.level())) {
            return;
        }
        boolean wasAtBottom = isScrolledToBottom();
        textArea.appendLine(LogLine.of(entry));
        if (wasAtBottom) {
            textArea.setCaretPosition(textArea.getDocument().getLength());
        }
    }

    private void forgetLine(Eviction eviction, LogLevelFilter filter) {
        if (filter.accepts(eviction.entry().level())) {
            textArea.removeLines(shownLinesBefore(eviction.position(), filter), LogLine.lineCount(eviction.entry()));
        }
    }

    private int shownLinesBefore(int position, LogLevelFilter filter) {
        return entries.snapshot().subList(0, position).stream()
                .filter(entry -> filter.accepts(entry.level())).mapToInt(LogLine::lineCount).sum();
    }

    private void rerender() {
        LogLevelFilter filter = selectedFilter();
        StringBuilder text = new StringBuilder();
        entries.snapshot().stream().filter(entry -> filter.accepts(entry.level()))
                .forEach(entry -> text.append(LogLine.of(entry)));
        textArea.replaceAll(text.toString());
        textArea.setCaretPosition(textArea.getDocument().getLength());
    }

    private void clear() {
        entries.clear();
        rerender();
    }

    private LogLevelFilter selectedFilter() {
        return (LogLevelFilter) levelFilter.getSelectedItem();
    }

    private boolean isScrolledToBottom() {
        JScrollBar vbar = scrollPane.getVerticalScrollBar();
        return (vbar.getValue() + vbar.getVisibleAmount()) >= vbar.getMaximum() - AUTO_SCROLL_THRESHOLD_PX;
    }

    private void copyAll() {
        StringSelection selection = new StringSelection(textArea.getText());
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
    }
}
