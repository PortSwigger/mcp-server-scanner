package com.mcpscanner.ui;

import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ToolAnnotations;
import com.mcpscanner.ui.widgets.SwingHtmlGuard;

class ToolTableModel extends SelectableInventoryTableModel<McpToolDefinition> {

    private static final String[] EXTRA_COLUMN_NAMES = {"Tool Name", "Annotations", "Description", "Parameters"};
    private static final int COLUMN_NAME = 0;
    static final int COLUMN_ANNOTATIONS = 1;
    private static final int COLUMN_DESCRIPTION = 2;
    private static final int COLUMN_PARAMETERS = 3;

    static final String LABEL_READ_ONLY = "Read-only";
    static final String LABEL_DESTRUCTIVE = "Destructive";
    static final String LABEL_NOT_SPECIFIED = "Not specified";

    @Override
    protected String[] extraColumnNames() {
        return EXTRA_COLUMN_NAMES;
    }

    @Override
    protected Object extraValueAt(McpToolDefinition tool, int extraColumnIndex) {
        return switch (extraColumnIndex) {
            case COLUMN_NAME -> tool.name();
            case COLUMN_ANNOTATIONS -> annotationLabel(tool.annotations());
            case COLUMN_DESCRIPTION -> tool.description();
            case COLUMN_PARAMETERS -> tool.inputSchema();
            default -> null;
        };
    }

    static String annotationLabel(ToolAnnotations annotations) {
        return switch (annotations.classify()) {
            case READ_ONLY -> LABEL_READ_ONLY;
            case DESTRUCTIVE -> LABEL_DESTRUCTIVE;
            case NOT_SPECIFIED -> LABEL_NOT_SPECIFIED;
        };
    }

    static String annotationTooltip(ToolAnnotations annotations) {
        StringBuilder sb = new StringBuilder(annotationLabel(annotations));
        appendAnnotationField(sb, "title", annotations.title());
        appendAnnotationField(sb, "readOnlyHint", annotations.readOnlyHint());
        appendAnnotationField(sb, "destructiveHint", annotations.destructiveHint());
        appendAnnotationField(sb, "idempotentHint", annotations.idempotentHint());
        appendAnnotationField(sb, "openWorldHint", annotations.openWorldHint());
        return sb.toString();
    }

    private static void appendAnnotationField(StringBuilder sb, String name, Object value) {
        if (value == null) {
            return;
        }
        sb.append("  |  ").append(name).append('=').append(SwingHtmlGuard.escapeHtml(value.toString()));
    }
}
