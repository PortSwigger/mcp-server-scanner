package com.mcpscanner.scan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.NullNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.McpObjectMapper;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public final class ObjectArrayFit {

    public static final int MOST_ELEMENTS = 5;

    private static final List<String> COMPOSITIONS = List.of("allOf", "anyOf", "oneOf");
    private static final String NULL_TYPE = "null";
    private static final String ARRAY_TYPE = "array";

    private ObjectArrayFit() {
    }

    public static boolean describes(JsonNode propertySchema) {
        return typed(propertySchema, ARRAY_TYPE) && !itemProperties(propertySchema).isEmpty();
    }

    public static boolean overlaps(JsonNode propertySchema, JsonNode array) {
        Map<String, ItemProperty> declared = itemProperties(propertySchema);
        return array.isArray() && elements(array).anyMatch(element -> keys(element).keySet().stream()
                .anyMatch(declared::containsKey));
    }

    public static ArrayNode fit(JsonNode propertySchema, JsonNode array) {
        Collection<ItemProperty> declared = itemProperties(propertySchema).values();
        ArrayNode fitted = McpObjectMapper.INSTANCE.createArrayNode();
        elements(array).limit(MOST_ELEMENTS).forEach(element -> fitted.add(fitted(declared, element)));
        return fitted;
    }

    private static Stream<JsonNode> elements(JsonNode array) {
        return StreamSupport.stream(array.spliterator(), false).filter(JsonNode::isObject);
    }

    private static ObjectNode fitted(Collection<ItemProperty> declared, JsonNode element) {
        Map<String, JsonNode> present = keys(element);
        ObjectNode fitted = McpObjectMapper.INSTANCE.createObjectNode();
        declared.forEach(property -> {
            JsonNode value = present.get(normalised(property.name()));
            if (value != null) {
                fitted.set(property.name(), value);
            } else if (property.nullable()) {
                fitted.set(property.name(), NullNode.getInstance());
            }
        });
        return fitted;
    }

    private static Map<String, JsonNode> keys(JsonNode element) {
        Map<String, JsonNode> keys = new HashMap<>();
        element.fields().forEachRemaining(field -> keys.put(normalised(field.getKey()), field.getValue()));
        return keys;
    }

    private static Map<String, ItemProperty> itemProperties(JsonNode propertySchema) {
        Map<String, ItemProperty> found = new LinkedHashMap<>();
        collect(propertySchema.path("items"), found);
        return found;
    }

    private static void collect(JsonNode schema, Map<String, ItemProperty> found) {
        schema.path("properties").fields().forEachRemaining(property -> found.merge(normalised(property.getKey()),
                new ItemProperty(property.getKey(), typed(property.getValue(), NULL_TYPE)), ItemProperty::merge));
        COMPOSITIONS.forEach(composition -> schema.path(composition).forEach(branch -> collect(branch, found)));
    }

    private static boolean typed(JsonNode schema, String type) {
        JsonNode declared = schema.path("type");
        if (declared.isArray()) {
            for (JsonNode candidate : declared) {
                if (type.equals(candidate.asText())) {
                    return true;
                }
            }
            return false;
        }
        return type.equals(declared.asText());
    }

    private static String normalised(String name) {
        return name.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }

    private record ItemProperty(String name, boolean nullable) {

        ItemProperty merge(ItemProperty other) {
            return new ItemProperty(name, nullable || other.nullable);
        }
    }
}
