package com.mcpscanner.scan;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpToolDefinition;

import java.math.BigDecimal;
import java.util.Map;
import java.util.Set;

public final class OwnedArguments {

    private static final Set<String> NUMERIC_TYPES = Set.of("integer", "number");

    private OwnedArguments() {
    }

    public static ScanInventory apply(ScanInventory inventory, OwnerArgumentSource owned) {
        return new ScanInventory(inventory.tools().stream().map(tool -> apply(tool, owned.forTool(tool))).toList(),
                inventory.resources(), inventory.resourceTemplates(), inventory.prompts());
    }

    public static McpToolDefinition apply(McpToolDefinition tool, Map<String, String> ownedObjects) {
        if (ownedObjects.isEmpty()) {
            return tool;
        }
        try {
            JsonNode schema = McpObjectMapper.INSTANCE.readTree(tool.inputSchema());
            boolean changed = withDefaults(schema.path("properties"), ownedObjects);
            return changed ? new McpToolDefinition(tool.name(), tool.description(),
                    McpObjectMapper.INSTANCE.writeValueAsString(schema), tool.icons(), tool.annotations()) : tool;
        } catch (JsonProcessingException | RuntimeException unreadable) {
            return tool;
        }
    }

    private static boolean withDefaults(JsonNode properties, Map<String, String> ownedObjects) {
        boolean changed = false;
        for (Map.Entry<String, String> owned : ownedObjects.entrySet()) {
            if (!owned.getValue().isBlank() && properties.get(owned.getKey()) instanceof ObjectNode property) {
                setDefault(property, owned.getValue());
                changed = true;
            }
        }
        return changed;
    }

    private static void setDefault(ObjectNode property, String value) {
        JsonNode array = ObjectArrayFit.describes(property) ? objectArray(value) : null;
        if (array != null) {
            property.set("default", ObjectArrayFit.fit(property, array));
        } else if (NUMERIC_TYPES.contains(property.path("type").asText()) && numeric(value)) {
            property.put("default", new BigDecimal(value));
        } else {
            property.put("default", value);
        }
    }

    private static JsonNode objectArray(String value) {
        try {
            JsonNode parsed = McpObjectMapper.INSTANCE.readTree(value);
            return parsed != null && parsed.isArray() ? parsed : null;
        } catch (JsonProcessingException notJson) {
            return null;
        }
    }

    private static boolean numeric(String value) {
        try {
            new BigDecimal(value);
            return true;
        } catch (NumberFormatException notNumeric) {
            return false;
        }
    }
}
