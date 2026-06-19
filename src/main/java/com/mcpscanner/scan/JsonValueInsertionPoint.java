package com.mcpscanner.scan;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointType;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.scan.ArgumentValueLocator.ValueKind;

import java.nio.charset.StandardCharsets;
import java.util.List;

class JsonValueInsertionPoint implements AuditInsertionPoint {

    static final String INSERTION_POINT_NAME_PREFIX = "MCP arg: ";

    private static final ObjectMapper MAPPER = McpObjectMapper.INSTANCE;

    private final String name;
    private final HttpRequest baseRequest;
    private final String baseValue;
    private final int valueStartInBody;
    private final int valueEndInBody;
    private final ValueKind kind;

    JsonValueInsertionPoint(String parameterName, HttpRequest baseRequest, String baseValue,
                            int valueStartInBody, int valueEndInBody, ValueKind kind) {
        this.name = INSERTION_POINT_NAME_PREFIX + parameterName;
        this.baseRequest = baseRequest;
        this.baseValue = baseValue;
        this.valueStartInBody = valueStartInBody;
        this.valueEndInBody = valueEndInBody;
        this.kind = kind;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public String baseValue() {
        return baseValue;
    }

    @Override
    public AuditInsertionPointType type() {
        return AuditInsertionPointType.PARAM_JSON;
    }

    @Override
    public HttpRequest buildHttpRequestWithPayload(ByteArray payload) {
        byte[] bodyBytes = baseRequest.bodyToString().getBytes(StandardCharsets.UTF_8);
        byte[] encoded = encodeForKind(payload.toString()).getBytes(StandardCharsets.UTF_8);
        byte[] newBody = new byte[valueStartInBody + encoded.length + (bodyBytes.length - valueEndInBody)];
        System.arraycopy(bodyBytes, 0, newBody, 0, valueStartInBody);
        System.arraycopy(encoded, 0, newBody, valueStartInBody, encoded.length);
        System.arraycopy(bodyBytes, valueEndInBody, newBody, valueStartInBody + encoded.length,
                bodyBytes.length - valueEndInBody);
        return baseRequest.withBody(new String(newBody, StandardCharsets.UTF_8));
    }

    @Override
    public List<Range> issueHighlights(ByteArray payload) {
        byte[] encoded = encodeForKind(payload.toString()).getBytes(StandardCharsets.UTF_8);
        int start = baseRequest.bodyOffset() + valueStartInBody;
        int end = start + encoded.length;
        return List.of(Range.range(start, end));
    }

    // The kind drives encoding: a payload that parses as a JSON literal of the declared
    // scalar kind goes in raw; anything else is wrapped as a JSON-escaped string so the
    // surrounding object remains valid JSON.
    private String encodeForKind(String payload) {
        return matchesKind(payload) ? payload : asJsonString(payload);
    }

    private boolean matchesKind(String payload) {
        if (kind == ValueKind.STRING) {
            return false;
        }
        try {
            JsonNode node = MAPPER.readTree(payload);
            return switch (kind) {
                case NUMBER -> node.isNumber();
                case BOOLEAN -> node.isBoolean();
                case NULL -> node.isNull();
                default -> false;
            };
        } catch (JsonProcessingException e) {
            return false;
        }
    }

    private String asJsonString(String payload) {
        try {
            return MAPPER.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            return "\"" + payload + "\"";
        }
    }
}
