package com.mcpscanner.checks;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.mcpscanner.mcp.JsonRpcBody;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.scan.JsonSchemaDefaults;

import java.util.LinkedHashMap;
import java.util.Map;

final class ToolsCallBodyBuilder {

    private ToolsCallBodyBuilder() {}

    static String buildToolsCallBody(ToolArgument argument, String payloadValue) {
        return buildEnvelope(argument.tool().name(), buildArgumentsMap(argument, payloadValue));
    }

    /** A {@code tools/call} for a read-only no-argument discovery tool
     *  (e.g. {@code list_allowed_directories}). */
    static String buildNoArgToolsCallBody(String toolName) {
        return buildEnvelope(toolName, new LinkedHashMap<>());
    }

    private static String buildEnvelope(String toolName, Map<String, Object> arguments) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("name", toolName);
        params.put("arguments", arguments);
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("jsonrpc", "2.0");
        envelope.put("id", JsonRpcBody.nextRequestId());
        envelope.put("method", "tools/call");
        envelope.put("params", params);
        try {
            return McpObjectMapper.INSTANCE.writeValueAsString(envelope);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialise tools/call body", e);
        }
    }

    private static Map<String, Object> buildArgumentsMap(ToolArgument argument, String payloadValue) {
        String schemaJson = argument.tool().inputSchema().toString();
        Map<String, Object> defaults = parseDefaults(schemaJson);
        defaults.put(argument.name(), payloadValue);
        return defaults;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseDefaults(String schemaJson) {
        try {
            String defaultsJson = JsonSchemaDefaults.buildDefaultArgumentsJson(schemaJson);
            Map<String, Object> parsed = McpObjectMapper.INSTANCE.readValue(defaultsJson, Map.class);
            return new LinkedHashMap<>(parsed);
        } catch (Exception ignored) {
            return new LinkedHashMap<>();
        }
    }
}
