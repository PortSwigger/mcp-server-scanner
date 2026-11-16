package com.mcpscanner.scan;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.mcp.McpObjectMapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public final class JsonSchemaDefaults {

    private static final ObjectMapper MAPPER = McpObjectMapper.INSTANCE;
    private static final String PLACEHOLDER_STRING = StringPlaceholder.PLAIN;
    private static final String ARRAY = "array";

    private JsonSchemaDefaults() {}

    public static String buildDefaultArgumentsJson(String inputSchemaJson) {
        try {
            Map<String, Object> schema = parseSchema(inputSchemaJson);
            Map<String, Object> arguments = buildObjectValue(argumentObjectSchema(schema));
            return MAPPER.writeValueAsString(arguments);
        } catch (JsonProcessingException e) {
            return EMPTY_ARGUMENTS_JSON;
        }
    }

    private static final String EMPTY_ARGUMENTS_JSON = "{}";

    public static ObjectNode defaultArguments(String inputSchemaJson) {
        try {
            JsonNode arguments = MAPPER.readTree(buildDefaultArgumentsJson(inputSchemaJson));
            return arguments instanceof ObjectNode object ? object : MAPPER.createObjectNode();
        } catch (JsonProcessingException | RuntimeException unreadable) {
            return MAPPER.createObjectNode();
        }
    }

    public static Map<ArgumentPath, JsonNode> withheldArguments(String inputSchemaJson) {
        try {
            Map<ArgumentPath, JsonNode> withheld = new LinkedHashMap<>();
            collectWithheld(argumentObjectSchema(parseSchema(inputSchemaJson)), new ArgumentPath(List.of()), withheld);
            return withheld;
        } catch (JsonProcessingException | RuntimeException unreadable) {
            return Map.of();
        }
    }

    private static void collectWithheld(Map<String, Object> objectSchema, ArgumentPath parent,
                                        Map<ArgumentPath, JsonNode> withheld) {
        placeholdersOf(objectSchema).forEach((name, placeholder) -> {
            ArgumentPath path = parent.child(name);
            if (placeholder.withheld()) {
                withheld.put(path, MAPPER.valueToTree(placeholder.value()));
            } else if (placeholder.value() instanceof Map<?, ?> && placeholder.builtFromProperties()) {
                collectWithheld(argumentObjectSchema(placeholder.schema()), path, withheld);
            } else if (placeholder.value() instanceof List<?> && placeholder.builtFromProperties()) {
                collectWithheldInItems(placeholder.schema(), path, withheld);
            }
        });
    }

    private static void collectWithheldInItems(Map<String, Object> arraySchema, ArgumentPath array,
                                               Map<ArgumentPath, JsonNode> withheld) {
        Map<String, Object> itemSchema = asMap(arraySchema.get("items"));
        if (itemSchema != null && mayHoldAnItem(arraySchema)) {
            collectWithheld(argumentObjectSchema(itemSchema), array.firstItem(), withheld);
        }
    }

    public static ObjectNode requiredArguments(String inputSchemaJson) {
        ObjectNode arguments = defaultArguments(inputSchemaJson);
        JsonNode schema = readable(inputSchemaJson);
        List<String> kept = new ArrayList<>();
        arguments.fieldNames().forEachRemaining(name -> {
            if (requiredOrDefaulted(schema, name)) {
                kept.add(name);
            }
        });
        arguments.retain(kept);
        return arguments;
    }

    private static boolean requiredOrDefaulted(JsonNode schema, String argument) {
        boolean required = false;
        for (JsonNode name : schema.path("required")) {
            required |= name.asText().equals(argument);
        }
        return required || schema.path("properties").path(argument).has("default");
    }

    private static JsonNode readable(String inputSchemaJson) {
        try {
            return MAPPER.readTree(inputSchemaJson);
        } catch (JsonProcessingException | RuntimeException unreadable) {
            return MAPPER.createObjectNode();
        }
    }

    private static Map<String, Object> argumentObjectSchema(Map<String, Object> schema) {
        if (schema.containsKey("properties")) {
            return schema;
        }
        Map<String, Object> composed = resolveComposition(schema);
        return composed == null ? schema : argumentObjectSchema(composed);
    }

    private static Map<String, Object> parseSchema(String inputSchemaJson) throws JsonProcessingException {
        return MAPPER.readValue(inputSchemaJson, new TypeReference<>() {});
    }

    private static Object resolve(String name, Map<String, Object> propertySchema) {
        Optional<List<Object>> items = fuzzableStringArray(name, propertySchema);
        if (items.isPresent()) {
            return items.get();
        }
        for (String declared : List.of("default", "const")) {
            if (propertySchema.containsKey(declared)) {
                return propertySchema.get(declared);
            }
        }
        Map<String, Object> composed = resolveComposition(propertySchema);
        if (composed != null) {
            return resolve(name, composed);
        }
        if (propertySchema.containsKey("enum")) {
            return firstEnumValue(propertySchema);
        }
        if (propertySchema.get("examples") instanceof List<?> examples && !examples.isEmpty()) {
            return examples.get(0);
        }
        return resolveByType(name, propertySchema);
    }

    private static Optional<List<Object>> fuzzableStringArray(String name, Map<String, Object> propertySchema) {
        Map<String, Object> array = arraySchema(propertySchema);
        Map<String, Object> items = array == null ? null : asMap(array.get("items"));
        if (items == null || !emptyByDefault(propertySchema) || !mayHoldAnItem(array)
                || !"string".equals(declaredType(items))) {
            return Optional.empty();
        }
        return Optional.of(List.of(resolve(name, items)));
    }

    private static boolean emptyByDefault(Map<String, Object> propertySchema) {
        Object declared = propertySchema.get("default");
        return declared == null || declared instanceof List<?> list && list.isEmpty();
    }

    private static boolean mayHoldAnItem(Map<String, Object> array) {
        return asInt(array.get("maxItems"), 1) >= 1;
    }

    private static Map<String, Object> arraySchema(Map<String, Object> propertySchema) {
        if (ARRAY.equals(declaredType(propertySchema))) {
            return propertySchema;
        }
        if (propertySchema.get("anyOf") instanceof List<?> alternatives) {
            return alternatives.stream().map(JsonSchemaDefaults::asMap).filter(Objects::nonNull)
                    .filter(alternative -> ARRAY.equals(declaredType(alternative))).findFirst().orElse(null);
        }
        return null;
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
        return defaultForType(declaredType(propertySchema));
    }

    private static Object resolveByType(String name, Map<String, Object> propertySchema) {
        String type = declaredType(propertySchema);
        if (type == null) {
            return PLACEHOLDER_STRING;
        }
        return switch (type) {
            case "string" -> StringPlaceholder.forProperty(name, propertySchema);
            case "integer" -> buildIntegerValue(propertySchema);
            case "number" -> buildNumberValue(propertySchema);
            case "boolean" -> Boolean.FALSE;
            case "array" -> buildArrayValue(name, propertySchema);
            case "object" -> buildObjectValue(propertySchema);
            default -> PLACEHOLDER_STRING;
        };
    }

    private static String declaredType(Map<String, Object> propertySchema) {
        Object type = propertySchema.get("type");
        if (type instanceof List<?> types) {
            return types.stream().filter(String.class::isInstance).map(String.class::cast)
                    .filter(name -> !"null".equals(name)).findFirst().orElse(null);
        }
        return type instanceof String name ? name : null;
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

    private static long buildIntegerValue(Map<String, Object> propertySchema) {
        return (long) Math.ceil(boundedNumber(propertySchema, 1));
    }

    private static double buildNumberValue(Map<String, Object> propertySchema) {
        return boundedNumber(propertySchema, 0.5);
    }

    private static double boundedNumber(Map<String, Object> propertySchema, double step) {
        if (propertySchema.get("minimum") instanceof Number minimum) {
            return minimum.doubleValue();
        }
        if (propertySchema.get("exclusiveMinimum") instanceof Number exclusiveMinimum) {
            return Math.floor(exclusiveMinimum.doubleValue()) + 1;
        }
        double upper = propertySchema.get("maximum") instanceof Number maximum ? maximum.doubleValue() : 1.0;
        if (propertySchema.get("exclusiveMaximum") instanceof Number exclusiveMaximum) {
            upper = Math.min(upper, exclusiveMaximum.doubleValue() - step);
        }
        return Math.min(1.0, upper);
    }

    private static List<Object> buildArrayValue(String name, Map<String, Object> propertySchema) {
        int minItems = asInt(propertySchema.get("minItems"), 0);
        if (minItems <= 0) {
            return List.of();
        }
        Map<String, Object> itemSchema = asMap(propertySchema.get("items"));
        Object element = itemSchema != null ? resolve(name, itemSchema) : PLACEHOLDER_STRING;
        List<Object> values = new ArrayList<>(minItems);
        for (int i = 0; i < minItems; i++) {
            values.add(element);
        }
        return values;
    }

    private static Map<String, Object> buildObjectValue(Map<String, Object> propertySchema) {
        Map<String, Object> values = new LinkedHashMap<>();
        placeholdersOf(propertySchema).forEach((name, placeholder) -> {
            if (!placeholder.withheld()) {
                values.put(name, placeholder.value());
            }
        });
        return values;
    }

    private static Map<String, Placeholder> placeholdersOf(Map<String, Object> objectSchema) {
        Map<String, Object> properties = asMap(objectSchema.get("properties"));
        Map<String, Placeholder> placeholders = new LinkedHashMap<>();
        if (properties == null) {
            return placeholders;
        }
        for (Map.Entry<String, Object> entry : properties.entrySet()) {
            Map<String, Object> child = asMap(entry.getValue());
            if (child != null) {
                Object value = resolve(entry.getKey(), child);
                placeholders.put(entry.getKey(), new Placeholder(value, child,
                        starvesTheCall(objectSchema, entry.getKey(), child, value)));
            }
        }
        return placeholders;
    }

    private record Placeholder(Object value, Map<String, Object> schema, boolean withheld) {

        boolean builtFromProperties() {
            return DECLARED_VALUES.stream().noneMatch(schema::containsKey);
        }
    }

    private static final List<String> DECLARED_VALUES = List.of("default", "const", "enum", "examples");

    private static boolean starvesTheCall(Map<String, Object> objectSchema, String name,
                                          Map<String, Object> property, Object placeholder) {
        if (isRequired(objectSchema, name) || property.containsKey("default")) {
            return false;
        }
        return placeholder instanceof String && property.containsKey("pattern") || boundOnly(property);
    }

    private static boolean boundOnly(Map<String, Object> property) {
        boolean numeric = "integer".equals(declaredType(property)) || "number".equals(declaredType(property));
        boolean declared = DECLARED_VALUES.stream().anyMatch(property::containsKey);
        return numeric && !declared && (property.containsKey("minimum") || property.containsKey("exclusiveMinimum"));
    }

    private static boolean isRequired(Map<String, Object> objectSchema, String name) {
        return objectSchema.get("required") instanceof List<?> required && required.contains(name);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : null;
    }

    private static int asInt(Object value, int fallback) {
        return value instanceof Number number ? number.intValue() : fallback;
    }
}
