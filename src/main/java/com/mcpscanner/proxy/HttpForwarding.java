package com.mcpscanner.proxy;

import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.ProtocolHttpRequest;
import com.mcpscanner.client.ProtocolHttpResponse;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.core.protocol.McpFlow;
import com.mcpscanner.core.protocol.McpRequests;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;

final class HttpForwarding implements ForwardingStrategy {

    private final McpScannerSession scannerSession;
    private final ProvenanceGuard guard;
    private final HttpForwardRequests requests;
    private final UpstreamHttp upstream;
    private final IsolatedHttpForwarder isolated;

    HttpForwarding(McpScannerSession scannerSession, ProvenanceGuard guard, HttpForwardRequests requests,
                   UpstreamHttp upstream, IsolatedHttpForwarder isolated) {
        this.scannerSession = scannerSession;
        this.guard = guard;
        this.requests = requests;
        this.upstream = upstream;
        this.isolated = isolated;
    }

    @Override
    public String label() {
        return "Proxy";
    }

    @Override
    public ProxyResponse forward(String body, Map<String, String> headers, AuditRequest audit)
            throws IOException, InterruptedException {
        if (SentinelHeaders.hasIdentity(headers)) {
            return forwardAsIdentity(audit.connection(), body, headers);
        }
        boolean unmanaged = SentinelHeaders.hasStripAuth(headers) || !audit.isManaged();
        String presentedSession = headerValue(headers, McpHeaders.SESSION_ID);
        if (presentedSession != null && !scannerSession.isIssuedSessionId(presentedSession)) {
            return forwardAsPresented(audit.connection(), body,
                    unmanaged ? headers : withSessionCredentials(headers));
        }
        if (opensASessionOfItsOwn(audit.connection(), body)) {
            return isolated.forwardInitialize(audit.connection(), body,
                    unmanaged ? headers : withSessionCredentials(headers));
        }
        if (unmanaged && presentedSession != null && SentinelHeaders.hasKeepSession(headers)) {
            return forwardOnLiveSession(audit.connection(), body, headers);
        }
        if (unmanaged) {
            return forwardUnmanaged(audit.connection(), body, headers);
        }
        return forwardAuthenticated(audit.connection(), body, headers);
    }

    private static boolean opensASessionOfItsOwn(ProxyConnection connection, String body) {
        return connection.transport() == TransportType.STREAMABLE_HTTP && McpRequestDetector.isInitializeBody(body);
    }

    private ProxyResponse forwardAsIdentity(ProxyConnection connection, String body, Map<String, String> headers)
            throws IOException, InterruptedException {
        if (McpRequestDetector.isInitializeBody(body)) {
            return relayingSessionId(connection, body, headers);
        }
        if (headerValue(headers, McpHeaders.SESSION_ID) != null) {
            return forwardAsPresented(connection, body, headers);
        }
        return forwardUnmanaged(connection, body, headers);
    }

    private Map<String, String> withSessionCredentials(Map<String, String> headers) {
        Map<String, String> withCredentials = new HashMap<>(headers);
        Map<String, String> session = scannerSession.scannerHeaders();
        scannerSession.credentialHeaderNames().forEach(name -> {
            String value = headerValue(session, name);
            if (value != null) {
                withCredentials.keySet().removeIf(name::equalsIgnoreCase);
                withCredentials.put(name, value);
            }
        });
        return withCredentials;
    }

    private Map<String, String> withLiveSessionId(Map<String, String> headers) {
        String liveSessionId = headerValue(scannerSession.protocolHeaders(), McpHeaders.SESSION_ID);
        if (liveSessionId == null) {
            return headers;
        }
        Map<String, String> live = new HashMap<>(headers);
        live.keySet().removeIf(McpHeaders.SESSION_ID::equalsIgnoreCase);
        live.put(McpHeaders.SESSION_ID, liveSessionId);
        return live;
    }

    private ProxyResponse forwardOnLiveSession(ProxyConnection connection, String body, Map<String, String> headers)
            throws IOException, InterruptedException {
        return send(guard.use(connection,
                () -> requests.post(connection.endpoint(), body, withLiveSessionId(headers))), body);
    }

    private ProxyResponse forwardAsPresented(ProxyConnection connection, String body, Map<String, String> headers)
            throws IOException, InterruptedException {
        return send(guard.use(connection, () -> requests.post(connection.endpoint(), body, headers)), body);
    }

    private ProxyResponse relayingSessionId(ProxyConnection connection, String body, Map<String, String> headers)
            throws IOException, InterruptedException {
        return send(guard.use(connection, () -> requests.post(connection.endpoint(), body, headers)), body, true);
    }

    private ProxyResponse send(ProtocolHttpRequest request, String body) throws IOException, InterruptedException {
        return send(request, body, false);
    }

    private ProxyResponse send(ProtocolHttpRequest request, String body, boolean relaySessionId)
            throws IOException, InterruptedException {
        try (ProtocolHttpResponse response = upstream.send(request)) {
            ProxyResponse reply = upstream.readReply(request, response, body);
            return relaySessionId ? withSessionId(reply, response) : reply;
        }
    }

    private static ProxyResponse withSessionId(ProxyResponse reply, ProtocolHttpResponse response) {
        return response.firstHeader(McpHeaders.SESSION_ID)
                .map(session -> reply.withHeader(McpHeaders.SESSION_ID, session))
                .orElse(reply);
    }

    private static String headerValue(Map<String, String> headers, String name) {
        return headers.entrySet().stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase(name))
                .map(Map.Entry::getValue)
                .findFirst()
                .orElse(null);
    }

    private ProxyResponse forwardAuthenticated(ProxyConnection connection, String body, Map<String, String> incoming) {
        McpFlow.HttpResponse response = guard.use(connection, () -> prepareAuthenticated(body, incoming)).get();
        String contentType = response.headers().entrySet().stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase("Content-Type"))
                .map(Map.Entry::getValue).findFirst().orElse("application/json");
        return new ProxyResponse(response.status(), contentType, response.body(), RelayedHeaders.of(response.headers()));
    }

    private Supplier<McpFlow.HttpResponse> prepareAuthenticated(String body, Map<String, String> incoming) {
        McpRequests.Request framed = requests.framed(body);
        Map<String, String> headers = new HashMap<>(requests.sessionHttpHeaders());
        incoming.forEach((name, value) -> {
            if (isForwardableOverSession(name)) headers.put(name, value);
        });
        var outgoing = new McpRequests.Request(framed.body(),
                HttpForwardRequests.withOperationHeaders(headers, framed.headers()));
        return scannerSession.prepareHttpOperation(outgoing);
    }

    private static boolean isForwardableOverSession(String name) {
        return ReservedHeaderPolicy.isForwardable(name)
                && !name.equalsIgnoreCase("Authorization")
                && !name.equalsIgnoreCase(McpHeaders.PROTOCOL_VERSION)
                && !name.equalsIgnoreCase(McpHeaders.SESSION_ID);
    }

    private ProxyResponse forwardUnmanaged(ProxyConnection connection, String body, Map<String, String> headers)
            throws IOException, InterruptedException {
        if (connection.transport() == TransportType.STREAMABLE_HTTP) {
            return isolated.forward(connection, body, headers);
        }
        return forwardAsPresented(connection, body, headers);
    }
}
