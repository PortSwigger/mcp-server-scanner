package com.mcpscanner.ui;

import com.mcpscanner.logging.McpEventLog;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public final class LoggerPanel extends JPanel {

    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss");
    private static final int AUTO_SCROLL_THRESHOLD_PX = 2;

    private final JTextArea textArea;
    private final JScrollPane scrollPane;

    public LoggerPanel(McpEventLog eventLog) {
        super(new BorderLayout());

        this.textArea = new JTextArea();
        this.textArea.setEditable(false);
        this.textArea.setLineWrap(false);
        this.textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        this.scrollPane = new JScrollPane(textArea);

        add(scrollPane, BorderLayout.CENTER);
        add(buildButtonRow(), BorderLayout.SOUTH);

        for (McpEventLog.LogEntry entry : eventLog.subscribe(this::onEntry)) {
            textArea.append(formatEntry(entry));
        }
    }

    private JPanel buildButtonRow() {
        JPanel row = new JPanel();
        row.setLayout(new BoxLayout(row, BoxLayout.LINE_AXIS));
        row.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));

        JButton copyButton = new JButton("Copy all");
        copyButton.addActionListener(e -> copyAll());

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> textArea.setText(""));

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
        boolean wasAtBottom = isScrolledToBottom();
        textArea.append(formatEntry(entry));
        if (wasAtBottom) {
            textArea.setCaretPosition(textArea.getDocument().getLength());
        }
    }

    private boolean isScrolledToBottom() {
        JScrollBar vbar = scrollPane.getVerticalScrollBar();
        return (vbar.getValue() + vbar.getVisibleAmount()) >= vbar.getMaximum() - AUTO_SCROLL_THRESHOLD_PX;
    }

    private void copyAll() {
        StringSelection selection = new StringSelection(textArea.getText());
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
    }

    private static String formatEntry(McpEventLog.LogEntry entry) {
        String time = LocalTime.ofInstant(entry.timestamp(), ZoneId.systemDefault()).format(TIME_FORMAT);
        return time + "  " + entry.level().name() + "  " + entry.message() + System.lineSeparator();
    }

    JTextArea textAreaForTest() {
        return textArea;
    }
}
