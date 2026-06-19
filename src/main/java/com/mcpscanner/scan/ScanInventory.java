package com.mcpscanner.scan;

import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.McpToolDefinition;

import java.util.List;

public record ScanInventory(
        List<McpToolDefinition> tools,
        List<McpResourceDefinition> resources,
        List<McpResourceTemplateDefinition> resourceTemplates,
        List<McpPromptDefinition> prompts) {

    public ScanInventory {
        tools = tools == null ? List.of() : List.copyOf(tools);
        resources = resources == null ? List.of() : List.copyOf(resources);
        resourceTemplates = resourceTemplates == null ? List.of() : List.copyOf(resourceTemplates);
        prompts = prompts == null ? List.of() : List.copyOf(prompts);
    }

    public static ScanInventory toolsOnly(List<McpToolDefinition> tools) {
        return new ScanInventory(tools, List.of(), List.of(), List.of());
    }

    public static ScanInventory empty() {
        return new ScanInventory(List.of(), List.of(), List.of(), List.of());
    }

    public int totalCount() {
        return tools.size() + resources.size() + resourceTemplates.size() + prompts.size();
    }
}
