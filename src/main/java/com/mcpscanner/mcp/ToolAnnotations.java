package com.mcpscanner.mcp;

public record ToolAnnotations(
        String title,
        Boolean readOnlyHint,
        Boolean destructiveHint,
        Boolean idempotentHint,
        Boolean openWorldHint
) {

    public static final ToolAnnotations EMPTY = new ToolAnnotations(null, null, null, null, null);

    public boolean isExplicitlyReadOnly() {
        return Boolean.TRUE.equals(readOnlyHint);
    }

    public boolean isAbsent() {
        return title == null
                && readOnlyHint == null
                && destructiveHint == null
                && idempotentHint == null
                && openWorldHint == null;
    }

    public Display classify() {
        if (isExplicitlyReadOnly()) {
            return Display.READ_ONLY;
        }
        if (isAbsent()) {
            return Display.NOT_SPECIFIED;
        }
        return Display.DESTRUCTIVE;
    }

    public enum Display {
        READ_ONLY,
        DESTRUCTIVE,
        NOT_SPECIFIED
    }
}
