package com.mcpscanner.ui.access;

import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ToolSafety;

import java.util.List;

record ToolsToCall(List<String> names, List<String> mayWrite) {

    ToolsToCall {
        names = List.copyOf(names);
        mayWrite = List.copyOf(mayWrite);
    }

    static ToolsToCall of(List<McpToolDefinition> tools) {
        return new ToolsToCall(tools.stream().map(McpToolDefinition::name).toList(),
                tools.stream().filter(ToolSafety::mayWrite).map(McpToolDefinition::name).toList());
    }

    boolean writes() {
        return !mayWrite.isEmpty();
    }

    boolean isEmpty() {
        return names.isEmpty();
    }
}
