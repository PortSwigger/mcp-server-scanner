package com.mcpscanner.mcp;

import java.util.Set;

public final class ToolSafety {

    private ToolSafety() {
    }

    public static boolean mayWrite(McpToolDefinition tool) {
        return !tool.annotations().isExplicitlyReadOnly();
    }

    public static ToolHarm harm(McpToolDefinition tool) {
        if (!mayWrite(tool)) {
            return ToolHarm.READ;
        }
        if (Boolean.TRUE.equals(tool.annotations().destructiveHint()) || WriteLikeName.destructive(tool.name())) {
            return ToolHarm.DESTRUCTIVE;
        }
        return nameSuggestsWrite(tool) || Boolean.FALSE.equals(tool.annotations().readOnlyHint())
                ? ToolHarm.WRITE : ToolHarm.POSSIBLE_READ;
    }

    public static boolean nameSuggestsWrite(McpToolDefinition tool) {
        return WriteLikeName.matches(tool.name());
    }

    public static boolean minable(McpToolDefinition tool, Set<String> optedIn) {
        return optedIn.contains(tool.name()) || readsOnly(tool);
    }

    public static boolean needsOptIn(McpToolDefinition tool) {
        return !readsOnly(tool);
    }

    public static boolean readsOnly(McpToolDefinition tool) {
        ToolAnnotations annotations = tool.annotations();
        if (Boolean.FALSE.equals(annotations.readOnlyHint()) || Boolean.TRUE.equals(annotations.destructiveHint())) {
            return false;
        }
        return annotations.isExplicitlyReadOnly() ? !nameSuggestsWrite(tool) : ReadLikeName.matches(tool.name());
    }
}
