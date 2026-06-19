package com.mcpscanner.ui;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.mcp.McpObjectMapper;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;
import java.util.Map;

public class ServerInfoPanel extends JPanel {

    private static final String EMPTY_SERVER_INFO = "Server did not advertise serverInfo.";
    private static final String EMPTY_INSTRUCTIONS = "Server did not return instructions.";
    private static final String EMPTY_CAPABILITIES = "Server did not advertise capabilities.";

    private final JTextArea serverInfoArea = buildReadOnlyArea();
    private final JTextArea instructionsArea = buildReadOnlyArea();
    private final JTextArea capabilitiesArea = buildMonospaceArea();

    public ServerInfoPanel() {
        super(new BorderLayout());
        Box stack = Box.createVerticalBox();
        stack.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        stack.add(buildSection("Server Info", serverInfoArea));
        stack.add(Box.createVerticalStrut(12));
        stack.add(buildSection("Instructions", instructionsArea));
        stack.add(Box.createVerticalStrut(12));
        stack.add(buildSection("Capabilities", capabilitiesArea));
        add(new JScrollPane(stack), BorderLayout.CENTER);

        populate(ServerMetadata.empty());
    }

    public void populate(ServerMetadata metadata) {
        serverInfoArea.setText(renderServerInfo(metadata.serverInfo()));
        serverInfoArea.setCaretPosition(0);
        instructionsArea.setText(renderInstructions(metadata.instructions()));
        instructionsArea.setCaretPosition(0);
        capabilitiesArea.setText(renderCapabilities(metadata.capabilities()));
        capabilitiesArea.setCaretPosition(0);
    }

    JTextArea serverInfoAreaForTest() {
        return serverInfoArea;
    }

    JTextArea instructionsAreaForTest() {
        return instructionsArea;
    }

    JTextArea capabilitiesAreaForTest() {
        return capabilitiesArea;
    }

    private static Component buildSection(String title, JTextArea content) {
        JPanel section = new JPanel(new BorderLayout());
        section.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel header = new JLabel(title);
        header.setFont(header.getFont().deriveFont(Font.BOLD, header.getFont().getSize() + 1f));
        header.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0));
        section.add(header, BorderLayout.NORTH);
        section.add(new JScrollPane(content), BorderLayout.CENTER);
        return section;
    }

    private static String renderServerInfo(Map<String, String> serverInfo) {
        if (serverInfo == null || serverInfo.isEmpty()) {
            return EMPTY_SERVER_INFO;
        }
        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> entry : serverInfo.entrySet()) {
            if (builder.length() > 0) {
                builder.append('\n');
            }
            builder.append(entry.getKey()).append(": ").append(entry.getValue());
        }
        return builder.toString();
    }

    private static String renderInstructions(String instructions) {
        if (instructions == null || instructions.isEmpty()) {
            return EMPTY_INSTRUCTIONS;
        }
        return instructions;
    }

    private static String renderCapabilities(Map<String, Object> capabilities) {
        if (capabilities == null || capabilities.isEmpty()) {
            return EMPTY_CAPABILITIES;
        }
        try {
            return McpObjectMapper.INSTANCE.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(capabilities);
        } catch (JsonProcessingException ex) {
            return capabilities.toString();
        }
    }

    private static JTextArea buildReadOnlyArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        return area;
    }

    private static JTextArea buildMonospaceArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }
}
