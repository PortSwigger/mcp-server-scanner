package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpResourceTemplateDefinition;

class ResourceTemplateTableModel extends SelectableInventoryTableModel<McpResourceTemplateDefinition> {

    private static final String[] EXTRA_COLUMN_NAMES = {"URI Template", "Name", "Description", "MIME Type"};
    private static final int COLUMN_URI_TEMPLATE = 0;
    private static final int COLUMN_NAME = 1;
    private static final int COLUMN_DESCRIPTION = 2;
    private static final int COLUMN_MIME_TYPE = 3;

    @Override
    protected String[] extraColumnNames() {
        return EXTRA_COLUMN_NAMES;
    }

    @Override
    protected Object extraValueAt(McpResourceTemplateDefinition template, int extraColumnIndex) {
        return switch (extraColumnIndex) {
            case COLUMN_URI_TEMPLATE -> template.uriTemplate();
            case COLUMN_NAME -> template.name();
            case COLUMN_DESCRIPTION -> template.description();
            case COLUMN_MIME_TYPE -> template.mimeType();
            default -> null;
        };
    }
}
