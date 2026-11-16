package com.mcpscanner.automation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpToolDefinition;

import java.util.Map;
import java.util.Optional;

record SeededArguments(String toolName, ObjectNode arguments) {

    private static final ObjectMapper JSON = McpObjectMapper.INSTANCE;
    private static final String TOOLS_CALL = "tools/call";

    static Optional<SeededArguments> of(SeedCall seed) {
        if (!TOOLS_CALL.equals(seed.method()) || seed.params() == null || !seed.params().path("name").isTextual()) {
            return Optional.empty();
        }
        JsonNode arguments = seed.params().path("arguments");
        return Optional.of(new SeededArguments(seed.params().get("name").asText(),
                arguments instanceof ObjectNode object ? object : JSON.createObjectNode()));
    }

    McpToolDefinition pinnedOn(McpToolDefinition tool) {
        ObjectNode schema = schemaOf(tool);
        schema.set("properties", pinnedProperties(schema.path("properties")));
        return new McpToolDefinition(tool.name(), tool.description(), schema.toString(), tool.icons(),
                tool.annotations(), tool.raw());
    }

    private ObjectNode pinnedProperties(JsonNode declared) {
        ObjectNode pinned = JSON.createObjectNode();
        for (Map.Entry<String, JsonNode> argument : arguments.properties()) {
            ObjectNode property = declared.get(argument.getKey()) instanceof ObjectNode object ? object.deepCopy()
                    : JSON.createObjectNode();
            property.set("default", argument.getValue().deepCopy());
            pinned.set(argument.getKey(), property);
        }
        return pinned;
    }

    private static ObjectNode schemaOf(McpToolDefinition tool) {
        try {
            return JSON.readTree(tool.inputSchema()) instanceof ObjectNode schema ? schema
                    : JSON.createObjectNode().put("type", "object");
        } catch (JsonProcessingException | RuntimeException unreadable) {
            return JSON.createObjectNode().put("type", "object");
        }
    }
}
