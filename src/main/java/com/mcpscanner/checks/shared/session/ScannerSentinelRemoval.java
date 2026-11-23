package com.mcpscanner.checks.shared.session;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.mcp.HeaderMutation;
import com.mcpscanner.mcp.ScannerSentinels;

import java.util.Map;

final class ScannerSentinelRemoval {

    private ScannerSentinelRemoval() {
    }

    static HttpRequest from(HttpRequest probe) {
        return HeaderMutation.apply(probe, ScannerSentinels.ALL, Map.of());
    }

    static HttpRequestResponse from(HttpRequestResponse exchange) {
        HttpRequest received = from(exchange.request());
        return received == exchange.request() ? exchange
                : HttpRequestResponse.httpRequestResponse(received, exchange.response(), exchange.annotations());
    }
}
