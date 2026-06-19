package com.mcpscanner.mcp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

public record McpToolDefinition(
        String name,
        String description,
        String inputSchema,
        List<IconDescriptor> icons,
        ToolAnnotations annotations) {

    public McpToolDefinition {
        icons = icons == null ? List.of() : List.copyOf(icons);
        annotations = annotations == null ? ToolAnnotations.EMPTY : annotations;
    }

    public McpToolDefinition(String name, String description, String inputSchema) {
        this(name, description, inputSchema, List.of(), ToolAnnotations.EMPTY);
    }

    public McpToolDefinition(String name, String description, String inputSchema, List<IconDescriptor> icons) {
        this(name, description, inputSchema, icons, ToolAnnotations.EMPTY);
    }

    public boolean hasProperties() {
        if (inputSchema == null || inputSchema.isEmpty()) {
            return false;
        }
        try {
            JsonNode root = McpObjectMapper.INSTANCE.readTree(inputSchema);
            JsonNode properties = root.path("properties");
            return !properties.isMissingNode() && properties.isObject();
        } catch (JsonProcessingException e) {
            return false;
        }
    }
}
