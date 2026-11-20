package com.mcpscanner.proxy;

import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.ProtocolHttpRequest;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.McpOperationFraming;
import com.mcpscanner.core.protocol.McpRequests;

import java.net.URI;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

final class HttpForwardRequests {

    private final McpScannerSession scannerSession;
    private final McpOperationFraming.Framer operationFramer;
    private final OperationHeaderFraming operationHeaderFraming = new OperationHeaderFraming();

    HttpForwardRequests(McpScannerSession scannerSession, McpOperationFraming.Framer operationFramer) {
        this.scannerSession = scannerSession;
        this.operationFramer = operationFramer;
    }

    ProtocolHttpRequest post(String endpoint, String body, Map<String, String> headers) {
        McpRequests.Request outgoing = isModern() ? modernRequest(body, headers) : new McpRequests.Request(body, headers);
        Map<String, String> forwarded = new LinkedHashMap<>();
        forwarded.put("Content-Type", "application/json");
        forwarded.put("Accept", "application/json, text/event-stream");
        applyForwardHeaders(forwarded, outgoing.headers());
        return new ProtocolHttpRequest(URI.create(endpoint), "POST", forwarded, outgoing.body());
    }

    McpRequests.Request framed(String body) {
        return isModern()
                ? ModernRequestAdapter.adapt(body, operationFramer)
                : new McpRequests.Request(body, sessionHttpHeaders());
    }

    Map<String, String> sessionHttpHeaders() {
        Map<String, String> headers = new HashMap<>(scannerSession.protocolHeaders());
        headers.put("Content-Type", McpHeaders.CONTENT_TYPE_JSON);
        headers.put("Accept", McpHeaders.ACCEPT_JSON_AND_SSE);
        return headers;
    }

    Map<String, String> operationHeaders(Map<String, String> outgoing, Map<String, String> framed,
                                         Map<String, String> incoming) {
        return operationHeaderFraming.frame(outgoing, framed, incoming);
    }

    private static Map<String, String> incoming(Map<String, String> headers) {
        return headers != null ? headers : Map.of();
    }

    private boolean isModern() {
        return scannerSession.transportType() == TransportType.MODERN_HTTP;
    }

    private McpRequests.Request modernRequest(String body, Map<String, String> headers) {
        var adapted = ModernRequestAdapter.adapt(body, operationFramer);
        return new McpRequests.Request(adapted.body(), operationHeaders(incoming(headers),
                adapted.headers(), incoming(headers)));
    }

    private void applyForwardHeaders(Map<String, String> forwardHeaders, Map<String, String> requestHeaders) {
        Map<String, String> incoming = requestHeaders != null ? requestHeaders : Map.of();
        Set<String> forwarded = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        incoming.forEach((name, value) -> {
            if (ReservedHeaderPolicy.isForwardable(name)) {
                forwardHeaders.put(name, value);
                forwarded.add(name);
            }
        });
        scannerSession.protocolHeaders().forEach((name, value) -> {
            if (!forwarded.contains(name) && !name.equalsIgnoreCase(McpHeaders.SESSION_ID)) {
                forwardHeaders.put(name, value);
            }
        });
    }
}
