package com.mcpscanner.client;

import com.fasterxml.jackson.databind.JsonNode;

import java.net.URI;
import java.util.Map;

/**
 * Best-effort reconstruction of a single langchain4j-mcp discovery exchange:
 * the JSON-RPC method name, the wire URL, the synthesised request body, the
 * request headers we know were applied, and the {@link JsonNode} response
 * envelope captured by {@link CapturingMcpTransport}.
 *
 * <p>Keeps the capture API free of Montoya types so the transport stays in
 * {@code client/} with no upward dependency. {@link McpDiscoveryAuditBridge}
 * is the only adapter that lifts this back into a Burp
 * {@link burp.api.montoya.http.message.HttpRequestResponse}.
 */
record CapturedExchange(
        String jsonRpcMethod,
        URI url,
        Map<String, String> requestHeaders,
        String requestBody,
        JsonNode responseEnvelope) {
}
