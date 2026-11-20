package com.mcpscanner.checks.shared.session;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.http.BurpMessages;
import com.mcpscanner.http.FlatHeaders;
import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.core.protocol.McpFlow;
import com.mcpscanner.core.protocol.McpRequests;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

final class BurpSessionPorts {

    private final Http http;
    private final String endpoint;
    private final Consumer<HttpRequestResponse> exchanges;
    private final RequestOptions options;
    private final StreamingFallback streaming;
    private final BurpMessages messages = new BurpMessages();

    BurpSessionPorts(Http http, String endpoint, Consumer<HttpRequestResponse> exchanges, RequestOptions options,
                     StreamingFallback streaming) {
        this.http = http;
        this.endpoint = endpoint;
        this.exchanges = exchanges;
        this.options = options;
        this.streaming = streaming;
    }

    McpFlow.HttpResponse post(McpRequests.Request request) {
        return send("POST", request.headers(), request.body());
    }

    McpFlow.HttpResponse delete(Map<String, String> headers) {
        return send("DELETE", headers, null);
    }

    private McpFlow.HttpResponse send(String method, Map<String, String> headers, String body) {
        HttpRequestResponse exchange = streaming.send(http,
                messages.toRequest(endpoint, method, BurpMessages.multiValued(directDelivery(headers)), body), options);
        if (exchange != null) {
            exchanges.accept(ScannerSentinelRemoval.from(exchange));
        }
        return exchange == null || exchange.response() == null ? null : toFlowResponse(exchange.response());
    }

    private static Map<String, String> directDelivery(Map<String, String> headers) {
        Map<String, String> marked = new LinkedHashMap<>(headers);
        marked.putAll(ScannerSentinels.directDeliveryOnly());
        return marked;
    }

    private static McpFlow.HttpResponse toFlowResponse(HttpResponse response) {
        boolean complete = BurpMessages.bodyWithin(response, BoundedBodyReader.MAX_RESPONSE_BYTES);
        String body = complete ? new String(BurpMessages.unframedBody(response), StandardCharsets.UTF_8) : "";
        return new McpFlow.HttpResponse(response.statusCode(), FlatHeaders.of(BurpMessages.groupedHeaders(response)),
                body, complete);
    }
}
