package com.mcpscanner.scan.request;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.auth.AuthHeaders;
import com.mcpscanner.http.ConnectionClose;
import com.mcpscanner.mcp.HttpOrigin;
import com.mcpscanner.mcp.FramedOperation;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.mcp.McpOperationFraming;
import com.mcpscanner.core.protocol.McpRequests;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.LongSupplier;
import java.util.regex.Pattern;

public final class McpHttpRequestFactory {

    private static final Pattern HEADER_NAME_TOKEN = Pattern.compile("^[A-Za-z0-9!#$%&'*+\\-.^_`|~]+$");
    private static final Set<String> FIXED_HEADERS = McpHeaders.caseInsensitive(
            "Content-Type", "Accept", ConnectionClose.HEADER, AuthHeaders.AUTHORIZATION_HEADER);

    private final LongSupplier idAllocator;
    private final McpOperationFraming.Framer framer;

    public McpHttpRequestFactory(LongSupplier idAllocator, McpOperationFraming.Framer framer) {
        this.idAllocator = idAllocator;
        this.framer = framer;
    }

    public HttpRequest build(String endpoint, McpMessage message, Map<String, String> sessionHeaders) {
        return HttpRequest.httpRequest(HttpOrigin.of(URI.create(endpoint)).toHttpService(),
                raw(endpoint, message, sessionHeaders));
    }

    public String raw(String endpoint, McpMessage message, Map<String, String> sessionHeaders) {
        McpRequests.Request framed = framed(message);
        String body = framed.body();
        URI uri = URI.create(endpoint);
        StringBuilder head = new StringBuilder()
                .append("POST ").append(requestTarget(uri)).append(" HTTP/1.1\r\n")
                .append("Host: ").append(HttpOrigin.of(uri).hostHeader()).append("\r\n")
                .append("Content-Type: ").append(McpHeaders.CONTENT_TYPE_JSON).append("\r\n")
                .append("Accept: ").append(McpHeaders.ACCEPT_JSON_AND_SSE).append("\r\n")
                .append(ConnectionClose.HEADER).append(": ").append(ConnectionClose.VALUE).append("\r\n")
                .append("Content-Length: ").append(body.getBytes(StandardCharsets.UTF_8).length).append("\r\n");
        wireHeaders(sessionHeaders, framed.headers()).forEach((name, value) -> appendHeader(head, name, value));
        return head.append("\r\n").append(body).toString();
    }

    private McpRequests.Request framed(McpMessage message) {
        ObjectNode params = message.params().map(ObjectNode::deepCopy).orElseGet(McpParams::empty);
        return message.notification()
                ? McpOperationFraming.notification(message.method(), params, framer)
                : McpOperationFraming.operation(message.method(), params, idAllocator.getAsLong(), framer);
    }

    private static Map<String, String> wireHeaders(Map<String, String> sessionHeaders, Map<String, String> framed) {
        Map<String, String> headers = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        headers.putAll(sessionHeaders);
        headers.putAll(framed);
        headers.keySet().removeIf(FIXED_HEADERS::contains);
        headers.put(ScannerSentinels.FRAMED_OPERATION_HEADER, FramedOperation.encode(headers));
        return headers;
    }

    private static void appendHeader(StringBuilder head, String name, String value) {
        if (name == null || !HEADER_NAME_TOKEN.matcher(name).matches()) {
            throw new IllegalArgumentException("Invalid HTTP header name: " + name);
        }
        if (value == null || value.chars().anyMatch(c -> c == '\r' || c == '\n' || c == '\0')) {
            throw new IllegalArgumentException("Invalid HTTP header value for " + name);
        }
        head.append(name).append(": ").append(value).append("\r\n");
    }

    private static String requestTarget(URI uri) {
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        return uri.getRawQuery() == null ? path : path + "?" + uri.getRawQuery();
    }
}
