package com.mcpscanner.access.mining;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.BigIntegerNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.scan.ObjectArrayFit;

import java.math.BigInteger;
import java.util.Set;

enum SlotType {
    STRING,
    INTEGER,
    OBJECTS,
    ANY;

    private static final Set<String> NUMERIC = Set.of("integer", "number");

    static SlotType of(JsonNode propertySchema) {
        String type = propertySchema.path("type").asText();
        if (ObjectArrayFit.describes(propertySchema)) {
            return OBJECTS;
        }
        if (NUMERIC.contains(type)) {
            return INTEGER;
        }
        return "string".equals(type) ? STRING : ANY;
    }

    boolean accepts(JsonNode value, JsonNode propertySchema) {
        return switch (this) {
            case OBJECTS -> ObjectArrayFit.overlaps(propertySchema, value);
            case INTEGER -> IdShape.integral(value);
            default -> value.isTextual() || value.isIntegralNumber();
        };
    }

    JsonNode stored(JsonNode value, JsonNode propertySchema) {
        return this == OBJECTS ? ObjectArrayFit.fit(propertySchema, value) : value;
    }

    JsonNode render(String value, JsonNode propertySchema) {
        return switch (this) {
            case OBJECTS -> ObjectArrayFit.fit(propertySchema, parsed(value));
            case INTEGER -> BigIntegerNode.valueOf(new BigInteger(value));
            default -> TextNode.valueOf(value);
        };
    }

    private static JsonNode parsed(String value) {
        try {
            return McpObjectMapper.INSTANCE.readTree(value);
        } catch (Exception unreadable) {
            throw new IllegalArgumentException("not an object array: " + value, unreadable);
        }
    }
}
