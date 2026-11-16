package com.mcpscanner.access;

import com.mcpscanner.mcp.ToolHarm;
import com.mcpscanner.mcp.ToolSafety;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ScanTarget;

import java.util.Optional;

public record AccessItem(AccessItemKey key, ScanTarget target) {

    public static AccessItem tool(McpToolDefinition tool) {
        return new AccessItem(new AccessItemKey(AccessItemKey.Kind.TOOL, tool.name()), new ScanTarget.Tool(tool));
    }

    public static AccessItem resource(McpResourceDefinition resource) {
        return new AccessItem(new AccessItemKey(AccessItemKey.Kind.RESOURCE, resource.uri()),
                new ScanTarget.Resource(resource));
    }

    public Optional<McpToolDefinition> tool() {
        return target instanceof ScanTarget.Tool toolTarget ? Optional.of(toolTarget.tool()) : Optional.empty();
    }

    public ToolHarm harm() {
        return tool().map(ToolSafety::harm).orElse(ToolHarm.READ);
    }

    public boolean writes() {
        return tool().map(ToolSafety::mayWrite).orElse(false);
    }
}
