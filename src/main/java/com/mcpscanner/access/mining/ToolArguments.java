package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpToolDefinition;

import java.util.ArrayList;
import java.util.List;

record ToolArguments(McpToolDefinition tool, List<ArgumentSlot> slots) {

    ToolArguments {
        slots = List.copyOf(slots);
    }

    static ToolArguments of(McpToolDefinition tool) {
        List<ArgumentSlot> slots = new ArrayList<>();
        properties(tool).fields().forEachRemaining(property -> {
            if (!SecretName.matches(property.getKey())) {
                slots.add(new ArgumentSlot(property.getKey(), Aliases.ofArgument(property.getKey(), tool.name()),
                        SlotType.of(property.getValue()), property.getValue()));
            }
        });
        return new ToolArguments(tool, slots);
    }

    private static JsonNode properties(McpToolDefinition tool) {
        try {
            return McpObjectMapper.INSTANCE.readTree(tool.inputSchema()).path("properties");
        } catch (Exception unreadable) {
            return McpObjectMapper.INSTANCE.createObjectNode();
        }
    }
}
