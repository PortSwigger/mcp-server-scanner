package com.mcpscanner.automation;

import burp.api.montoya.http.message.requests.HttpRequest;

public final class CheckProbeMarker {

    public static final String HEADER = "X-Mcp-Scanner-Check-Probe";
    private static final String VALUE = "1";

    private CheckProbeMarker() {
    }

    static HttpRequest marked(HttpRequest request) {
        return request.withAddedHeader(HEADER, VALUE);
    }

    static boolean carries(HttpRequest request) {
        return request.hasHeader(HEADER);
    }

    static HttpRequest stripped(HttpRequest request) {
        return request.withRemovedHeader(HEADER);
    }
}
