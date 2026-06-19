package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpResourceDefinition;

class ResourceTableModel extends SelectableInventoryTableModel<McpResourceDefinition> {

    private static final String[] EXTRA_COLUMN_NAMES = {"URI", "Name", "Description", "MIME Type"};
    private static final int COLUMN_URI = 0;
    private static final int COLUMN_NAME = 1;
    private static final int COLUMN_DESCRIPTION = 2;
    private static final int COLUMN_MIME_TYPE = 3;

    @Override
    protected String[] extraColumnNames() {
        return EXTRA_COLUMN_NAMES;
    }

    @Override
    protected Object extraValueAt(McpResourceDefinition resource, int extraColumnIndex) {
        return switch (extraColumnIndex) {
            case COLUMN_URI -> resource.uri();
            case COLUMN_NAME -> resource.name();
            case COLUMN_DESCRIPTION -> resource.description();
            case COLUMN_MIME_TYPE -> resource.mimeType();
            default -> null;
        };
    }
}
