package com.mcpscanner.scan;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.mcp.McpRequestKind;
import com.mcpscanner.scan.ArgumentValueLocator.ValueByteRange;
import com.mcpscanner.scan.ArgumentValueLocator.ValueKind;
import com.mcpscanner.scan.ArgumentsObjectLocator.ArgumentsObjectRange;
import com.mcpscanner.scan.UriValueLocator.UriValueRange;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public class McpInsertionPointProvider implements AuditInsertionPointProvider {

    @Override
    public List<AuditInsertionPoint> provideInsertionPoints(HttpRequestResponse baseHttpRequestResponse) {
        McpRequestKind kind = McpRequestDetector.classify(baseHttpRequestResponse);
        if (!kind.isMcp()) {
            return Collections.emptyList();
        }
        HttpRequest request = baseHttpRequestResponse.request();
        byte[] bodyBytes = request.bodyToString().getBytes(StandardCharsets.UTF_8);
        return switch (kind) {
            case TOOLS_CALL, PROMPTS_GET -> argumentsInsertionPoints(request, bodyBytes);
            case RESOURCES_READ -> uriInsertionPoint(request, bodyBytes);
            case TOOLS_LIST, OTHER_MCP, NOT_MCP -> Collections.emptyList();
        };
    }

    private List<AuditInsertionPoint> argumentsInsertionPoints(HttpRequest request, byte[] bodyBytes) {
        Optional<ArgumentsObjectRange> argumentsLocation = ArgumentsObjectLocator.locate(bodyBytes);
        if (argumentsLocation.isEmpty()) {
            return Collections.emptyList();
        }
        ArgumentsObjectRange range = argumentsLocation.get();
        byte[] argumentsBytes = Arrays.copyOfRange(bodyBytes, range.start(), range.end());
        Map<String, ValueByteRange> ranges = ArgumentValueLocator.locate(argumentsBytes);
        if (ranges.isEmpty()) {
            return Collections.emptyList();
        }
        return buildArgumentInsertionPoints(request, range.start(), ranges);
    }

    private List<AuditInsertionPoint> uriInsertionPoint(HttpRequest request, byte[] bodyBytes) {
        Optional<UriValueRange> uriRange = UriValueLocator.locate(bodyBytes);
        if (uriRange.isEmpty()) {
            return Collections.emptyList();
        }
        UriValueRange range = uriRange.get();
        String innerValue = bodySlice(request, range.innerStartInclusive(), range.innerEndExclusive());
        return List.of(new JsonValueInsertionPoint(
                "uri", request, innerValue, range.startInclusive(), range.endExclusive(), ValueKind.STRING));
    }

    private List<AuditInsertionPoint> buildArgumentInsertionPoints(HttpRequest request, int argumentsStart,
                                                                   Map<String, ValueByteRange> ranges) {
        List<AuditInsertionPoint> insertionPoints = new ArrayList<>();
        for (Map.Entry<String, ValueByteRange> entry : ranges.entrySet()) {
            ValueByteRange range = entry.getValue();
            if (isContainerKind(range.kind())) {
                continue;
            }
            insertionPoints.add(toArgumentInsertionPoint(request, argumentsStart, entry.getKey(), range));
        }
        return insertionPoints;
    }

    private boolean isContainerKind(ValueKind kind) {
        return kind == ValueKind.OBJECT || kind == ValueKind.ARRAY;
    }

    private AuditInsertionPoint toArgumentInsertionPoint(HttpRequest request, int argumentsStart,
                                                         String key, ValueByteRange range) {
        int valueStartInBody = argumentsStart + range.startInclusive();
        int valueEndInBody = argumentsStart + range.endExclusive();
        String baseValue = bodySlice(request, valueStartInBody, valueEndInBody);
        return new JsonValueInsertionPoint(key, request, baseValue, valueStartInBody, valueEndInBody, range.kind());
    }

    private String bodySlice(HttpRequest request, int startInBody, int endInBody) {
        byte[] bodyBytes = request.bodyToString().getBytes(StandardCharsets.UTF_8);
        return new String(bodyBytes, startInBody, endInBody - startInBody, StandardCharsets.UTF_8);
    }
}
