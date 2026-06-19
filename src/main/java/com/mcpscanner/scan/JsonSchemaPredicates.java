package com.mcpscanner.scan;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.HashSet;
import java.util.Set;

public final class JsonSchemaPredicates {

    private static final String STRING_TYPE = "string";
    private static final String REF_PREFIX = "#/";

    private JsonSchemaPredicates() {}

    public static boolean isStringSchema(JsonNode schema) {
        return isStringSchema(schema, null);
    }

    public static boolean isStringSchema(JsonNode schema, JsonNode root) {
        return isStringSchema(schema, root, new HashSet<>());
    }

    private static boolean isStringSchema(JsonNode schema, JsonNode root, Set<String> visitedRefs) {
        if (schema == null || schema.isNull() || !schema.isObject()) {
            return false;
        }
        if (hasLiteralStringType(schema)) {
            return true;
        }
        if (typeArrayContainsString(schema.path("type"))) {
            return true;
        }
        if (anyBranchIsString(schema.path("anyOf"), root, visitedRefs)
                || anyBranchIsString(schema.path("oneOf"), root, visitedRefs)) {
            return true;
        }
        return refResolvesToString(schema.path("$ref"), root, visitedRefs);
    }

    private static boolean hasLiteralStringType(JsonNode schema) {
        JsonNode type = schema.path("type");
        return type.isTextual() && STRING_TYPE.equals(type.asText());
    }

    private static boolean typeArrayContainsString(JsonNode typeNode) {
        if (!typeNode.isArray()) {
            return false;
        }
        for (JsonNode element : typeNode) {
            if (element.isTextual() && STRING_TYPE.equals(element.asText())) {
                return true;
            }
        }
        return false;
    }

    private static boolean anyBranchIsString(JsonNode branches, JsonNode root, Set<String> visitedRefs) {
        if (!branches.isArray()) {
            return false;
        }
        for (JsonNode branch : branches) {
            if (isStringSchema(branch, root, visitedRefs)) {
                return true;
            }
        }
        return false;
    }

    // Visited-set keyed by canonical pointer defends against composition
    // cycles like A -> anyOf[A] that the direct-ref guard alone cannot catch.
    private static boolean refResolvesToString(JsonNode refNode, JsonNode root, Set<String> visitedRefs) {
        if (root == null || !refNode.isTextual()) {
            return false;
        }
        String pointer = refNode.asText();
        if (!visitedRefs.add(pointer)) {
            return false;
        }
        JsonNode resolved = resolveLocalRef(pointer, root);
        if (resolved == null) {
            return false;
        }
        return isStringSchema(resolved, root, visitedRefs);
    }

    private static JsonNode resolveLocalRef(String pointer, JsonNode root) {
        if (!pointer.startsWith(REF_PREFIX)) {
            return null;
        }
        JsonNode cursor = root;
        for (String segment : pointer.substring(REF_PREFIX.length()).split("/")) {
            if (segment.isEmpty()) {
                continue;
            }
            cursor = cursor.path(decodeJsonPointerSegment(segment));
            if (cursor.isMissingNode()) {
                return null;
            }
        }
        return cursor;
    }

    private static String decodeJsonPointerSegment(String segment) {
        return segment.replace("~1", "/").replace("~0", "~");
    }
}
