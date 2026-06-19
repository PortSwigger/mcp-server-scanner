package com.mcpscanner.scan;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.mcp.McpObjectMapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class JsonSchemaDefaults {

    private static final ObjectMapper MAPPER = McpObjectMapper.INSTANCE;
    private static final String PLACEHOLDER_STRING = "test";
    private static final String EMAIL_PLACEHOLDER = "test@example.com";

    private JsonSchemaDefaults() {}

    public static String buildDefaultArgumentsJson(String inputSchemaJson) {
        try {
            Map<String, Object> schema = parseSchema(inputSchemaJson);
            Map<String, Object> arguments = buildObjectValue(schema);
            return MAPPER.writeValueAsString(arguments);
        } catch (JsonProcessingException e) {
            return EMPTY_ARGUMENTS_JSON;
        }
    }

    private static final String EMPTY_ARGUMENTS_JSON = "{}";

    private static Map<String, Object> parseSchema(String inputSchemaJson) throws JsonProcessingException {
        return MAPPER.readValue(inputSchemaJson, new TypeReference<>() {});
    }

    private static Object resolve(Map<String, Object> propertySchema) {
        if (propertySchema.containsKey("default")) {
            return propertySchema.get("default");
        }
        Map<String, Object> composed = resolveComposition(propertySchema);
        if (composed != null) {
            return resolve(composed);
        }
        if (propertySchema.containsKey("enum")) {
            return firstEnumValue(propertySchema);
        }
        return resolveByType(propertySchema);
    }

    private static Map<String, Object> resolveComposition(Map<String, Object> propertySchema) {
        for (String key : List.of("oneOf", "anyOf", "allOf")) {
            Map<String, Object> first = firstSubSchema(propertySchema.get(key));
            if (first != null) {
                return first;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> firstSubSchema(Object compositionNode) {
        if (compositionNode instanceof List<?> list && !list.isEmpty() && list.get(0) instanceof Map) {
            return (Map<String, Object>) list.get(0);
        }
        return null;
    }

    private static Object firstEnumValue(Map<String, Object> propertySchema) {
        Object values = propertySchema.get("enum");
        if (values instanceof List<?> list && !list.isEmpty()) {
            return list.get(0);
        }
        return defaultForType((String) propertySchema.get("type"));
    }

    private static Object resolveByType(Map<String, Object> propertySchema) {
        String type = (String) propertySchema.get("type");
        if (type == null) {
            return PLACEHOLDER_STRING;
        }
        return switch (type) {
            case "string" -> buildStringValue(propertySchema);
            case "integer" -> buildIntegerValue(propertySchema);
            case "number" -> buildNumberValue(propertySchema);
            case "boolean" -> Boolean.FALSE;
            case "array" -> buildArrayValue(propertySchema);
            case "object" -> buildObjectValue(propertySchema);
            default -> PLACEHOLDER_STRING;
        };
    }

    private static Object defaultForType(String type) {
        if (type == null) {
            return PLACEHOLDER_STRING;
        }
        return switch (type) {
            case "integer" -> 1L;
            case "number" -> 1.0;
            case "boolean" -> Boolean.FALSE;
            case "array" -> List.of();
            case "object" -> Map.of();
            default -> PLACEHOLDER_STRING;
        };
    }

    private static String buildStringValue(Map<String, Object> propertySchema) {
        if ("email".equals(propertySchema.get("format"))) {
            return EMAIL_PLACEHOLDER;
        }
        int minLength = asInt(propertySchema.get("minLength"), 0);
        if (minLength <= PLACEHOLDER_STRING.length()) {
            return PLACEHOLDER_STRING;
        }
        return PLACEHOLDER_STRING.repeat((minLength + PLACEHOLDER_STRING.length() - 1) / PLACEHOLDER_STRING.length())
                .substring(0, minLength);
    }

    private static long buildIntegerValue(Map<String, Object> propertySchema) {
        Object minimum = propertySchema.get("minimum");
        if (minimum instanceof Number number) {
            return number.longValue();
        }
        return 1L;
    }

    private static double buildNumberValue(Map<String, Object> propertySchema) {
        Object minimum = propertySchema.get("minimum");
        if (minimum instanceof Number number) {
            return number.doubleValue();
        }
        return 1.0;
    }

    private static List<Object> buildArrayValue(Map<String, Object> propertySchema) {
        int minItems = asInt(propertySchema.get("minItems"), 0);
        if (minItems <= 0) {
            return List.of();
        }
        Map<String, Object> itemSchema = asMap(propertySchema.get("items"));
        Object element = itemSchema != null ? resolve(itemSchema) : PLACEHOLDER_STRING;
        List<Object> values = new ArrayList<>(minItems);
        for (int i = 0; i < minItems; i++) {
            values.add(element);
        }
        return values;
    }

    private static Map<String, Object> buildObjectValue(Map<String, Object> propertySchema) {
        Map<String, Object> properties = asMap(propertySchema.get("properties"));
        if (properties == null || properties.isEmpty()) {
            return new LinkedHashMap<>();
        }
        Map<String, Object> values = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : properties.entrySet()) {
            Map<String, Object> child = asMap(entry.getValue());
            if (child == null) {
                continue;
            }
            values.put(entry.getKey(), resolve(child));
        }
        return values;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : null;
    }

    private static int asInt(Object value, int fallback) {
        return value instanceof Number number ? number.intValue() : fallback;
    }
}
