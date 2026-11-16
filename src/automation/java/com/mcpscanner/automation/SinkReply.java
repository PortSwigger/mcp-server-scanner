package com.mcpscanner.automation;

import burp.api.montoya.http.message.responses.HttpResponse;

public final class SinkReply {

    public static final String HEADER = "X-Mcp-Scanner-Sink";

    private SinkReply() {
    }

    public static boolean matches(HttpResponse response) {
        return response.hasHeader(HEADER);
    }
}
