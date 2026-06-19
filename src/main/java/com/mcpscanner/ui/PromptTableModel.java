package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.PromptArgument;

import java.util.List;
import java.util.stream.Collectors;

class PromptTableModel extends SelectableInventoryTableModel<McpPromptDefinition> {

    private static final String[] EXTRA_COLUMN_NAMES = {"Name", "Description", "Arguments"};
    private static final int COLUMN_NAME = 0;
    private static final int COLUMN_DESCRIPTION = 1;
    private static final int COLUMN_ARGUMENTS = 2;

    @Override
    protected String[] extraColumnNames() {
        return EXTRA_COLUMN_NAMES;
    }

    @Override
    protected Object extraValueAt(McpPromptDefinition prompt, int extraColumnIndex) {
        return switch (extraColumnIndex) {
            case COLUMN_NAME -> prompt.name();
            case COLUMN_DESCRIPTION -> prompt.description();
            case COLUMN_ARGUMENTS -> renderArguments(prompt.arguments());
            default -> null;
        };
    }

    private static String renderArguments(List<PromptArgument> arguments) {
        if (arguments == null || arguments.isEmpty()) {
            return "";
        }
        return arguments.stream()
                .map(arg -> arg.required() ? arg.name() + "*" : arg.name())
                .collect(Collectors.joining(", "));
    }
}
