package com.mcpscanner.checks.content;

import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;

import java.util.List;

public record DiscoveredContent(ServerMetadata serverInfo,
                                List<McpToolDefinition> tools,
                                List<McpResourceDefinition> resources,
                                List<McpResourceTemplateDefinition> resourceTemplates,
                                List<McpPromptDefinition> prompts) {

    public DiscoveredContent {
        tools = tools == null ? List.of() : List.copyOf(tools);
        resources = resources == null ? List.of() : List.copyOf(resources);
        resourceTemplates = resourceTemplates == null ? List.of() : List.copyOf(resourceTemplates);
        prompts = prompts == null ? List.of() : List.copyOf(prompts);
    }
}
