package com.mcpscanner.scan;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpToolDefinition;

import java.util.ArrayList;
import java.util.List;

public final class RequiredArguments {

    private RequiredArguments() {
    }

    public static McpToolDefinition only(McpToolDefinition tool) {
        try {
            JsonNode schema = McpObjectMapper.INSTANCE.readTree(tool.inputSchema());
            if (!(schema.path("properties") instanceof ObjectNode properties)) {
                return tool;
            }
            properties.retain(kept(schema, properties));
            return new McpToolDefinition(tool.name(), tool.description(),
                    McpObjectMapper.INSTANCE.writeValueAsString(schema), tool.icons(), tool.annotations());
        } catch (JsonProcessingException | RuntimeException unreadable) {
            return tool;
        }
    }

    private static List<String> kept(JsonNode schema, ObjectNode properties) {
        List<String> kept = new ArrayList<>();
        properties.fieldNames().forEachRemaining(name -> {
            if (required(schema, name) || properties.path(name).has("default")) {
                kept.add(name);
            }
        });
        return kept;
    }

    private static boolean required(JsonNode schema, String name) {
        for (JsonNode required : schema.path("required")) {
            if (name.equals(required.asText())) {
                return true;
            }
        }
        return false;
    }
}
