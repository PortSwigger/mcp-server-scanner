package com.mcpscanner.checks.api.crossidentity;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.shared.session.McpSessionHandshake;
import com.mcpscanner.checks.shared.session.SessionHeaders;

import java.util.function.Consumer;
import java.util.function.Function;

public final class SessionHandshake {

    private static final String INITIALIZE_ID = "mcp-scanner-identity-initialize";

    private final McpSessionHandshake handshake =
            McpSessionHandshake.defaultingTo(INITIALIZE_ID, ProtocolVariant.ABSENT_HEADER_HANDSHAKE_VERSION);
    private final Function<HttpRequest, HttpRequestResponse> transport;

    public SessionHandshake(Function<HttpRequest, HttpRequestResponse> transport) {
        this.transport = transport;
    }

    public HttpRequestResponse initialize(HttpRequest sessionless) {
        return transport.apply(handshake.initialize(sessionless));
    }

    public HttpRequest join(HttpRequest sessionless, String sessionId, Consumer<HttpRequest> opened) {
        HttpRequest joined = SessionHeaders.inSession(sessionless, sessionId);
        opened.accept(joined);
        transport.apply(handshake.initialized(sessionless, sessionId));
        return joined;
    }
}
