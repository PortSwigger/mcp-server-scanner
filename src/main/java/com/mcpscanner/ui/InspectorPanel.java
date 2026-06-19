package com.mcpscanner.ui;

import com.mcpscanner.logging.McpEventLog;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;

public final class InspectorPanel extends JPanel {

    private final JTabbedPane tabs;
    private final ServerConfigPanel connectionPanel;
    private final ScanChecksPanel checksPanel;
    private final LoggerPanel loggerPanel;

    public InspectorPanel(ServerConfigPanel connectionPanel, ScanChecksPanel checksPanel, McpEventLog eventLog) {
        super(new BorderLayout());
        this.connectionPanel = connectionPanel;
        this.checksPanel = checksPanel;
        this.loggerPanel = new LoggerPanel(eventLog);
        this.tabs = new JTabbedPane();
        this.tabs.addTab("Connection", connectionPanel);
        this.tabs.addTab("Checks", checksPanel);
        this.tabs.addTab("Log", loggerPanel);
        add(tabs, BorderLayout.CENTER);
    }

    public ServerConfigPanel connectionPanel() {
        return connectionPanel;
    }

    public ScanChecksPanel checksPanel() {
        return checksPanel;
    }

    public LoggerPanel loggerPanel() {
        return loggerPanel;
    }
}
