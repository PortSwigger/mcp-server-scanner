package com.mcpscanner.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class InitializeResponseParser {

    private InitializeResponseParser() {}

    public static Optional<String> parseProtocolVersion(String body) {
        return parseProtocolVersion(body, null);
    }

    public static Optional<String> parseProtocolVersion(String body, McpEventLog eventLog) {
        try {
            JsonNode versionNode = McpObjectMapper.INSTANCE.readTree(body)
                    .path("result").path("protocolVersion");
            return versionNode.isTextual() ? Optional.of(versionNode.textValue()) : Optional.empty();
        } catch (Exception e) {
            warnParseFailure(eventLog, "protocolVersion", e);
            return Optional.empty();
        }
    }

    public static Map<String, String> parseServerInfo(String body) {
        return parseServerInfo(body, null);
    }

    public static Map<String, String> parseServerInfo(String body, McpEventLog eventLog) {
        try {
            JsonNode root = McpObjectMapper.INSTANCE.readTree(body);
            JsonNode serverInfo = root.path("result").path("serverInfo");
            if (!serverInfo.isObject()) {
                return Map.of();
            }
            Map<String, String> fields = new LinkedHashMap<>();
            for (Map.Entry<String, JsonNode> entry : serverInfo.properties()) {
                fields.put(entry.getKey(), entry.getValue().asText());
            }
            return fields;
        } catch (Exception e) {
            warnParseFailure(eventLog, "serverInfo", e);
            return Map.of();
        }
    }

    public static String parseInstructions(String body) {
        return parseInstructions(body, null);
    }

    public static String parseInstructions(String body, McpEventLog eventLog) {
        try {
            JsonNode instructions = McpObjectMapper.INSTANCE.readTree(body)
                    .path("result").path("instructions");
            return instructions.isTextual() ? instructions.textValue() : "";
        } catch (Exception e) {
            warnParseFailure(eventLog, "instructions", e);
            return "";
        }
    }

    public static Map<String, Object> parseCapabilities(String body) {
        return parseCapabilities(body, null);
    }

    public static Map<String, Object> parseCapabilities(String body, McpEventLog eventLog) {
        try {
            JsonNode capabilities = McpObjectMapper.INSTANCE.readTree(body)
                    .path("result").path("capabilities");
            if (!capabilities.isObject()) {
                return Map.of();
            }
            Object converted = convert(capabilities);
            if (converted instanceof Map<?, ?> map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> typed = (Map<String, Object>) map;
                return typed;
            }
            return Map.of();
        } catch (Exception e) {
            warnParseFailure(eventLog, "capabilities", e);
            return Map.of();
        }
    }

    private static void warnParseFailure(McpEventLog eventLog, String field, Exception e) {
        (eventLog != null ? eventLog : McpEventLog.noop()).warn(
                "Initialize parse failure for " + field + ": " + e.getClass().getSimpleName());
    }

    private static Object convert(JsonNode node) {
        if (node.isObject()) {
            Map<String, Object> map = new LinkedHashMap<>();
            node.properties().forEach(e -> map.put(e.getKey(), convert(e.getValue())));
            return map;
        }
        if (node.isArray()) {
            List<Object> list = new ArrayList<>();
            node.forEach(child -> list.add(convert(child)));
            return list;
        }
        if (node.isBoolean()) {
            return node.booleanValue();
        }
        if (node.isNumber()) {
            return node.numberValue();
        }
        if (node.isTextual()) {
            return node.textValue();
        }
        return null;
    }
}
