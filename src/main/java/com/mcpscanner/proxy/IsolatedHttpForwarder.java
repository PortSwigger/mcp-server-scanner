package com.mcpscanner.proxy;

import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.ProtocolHttpRequest;
import com.mcpscanner.client.ProtocolHttpResponse;
import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.core.connection.ConnectionAuthException;
import com.mcpscanner.core.connection.CredentialProviders;
import com.mcpscanner.core.connection.McpConnection;
import com.mcpscanner.core.protocol.McpFlow;
import com.mcpscanner.core.protocol.McpRequests;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

final class IsolatedHttpForwarder {

    private static final int MAX_FLOW_MESSAGES = 32;

    private final McpScannerSession scannerSession;
    private final ProvenanceGuard guard;
    private final HttpForwardRequests requests;
    private final UpstreamHttp upstream;
    private final ClientIdentityProvider identityProvider;

    IsolatedHttpForwarder(McpScannerSession scannerSession, ProvenanceGuard guard, HttpForwardRequests requests,
                          UpstreamHttp upstream, ClientIdentityProvider identityProvider) {
        this.scannerSession = scannerSession;
        this.guard = guard;
        this.requests = requests;
        this.upstream = upstream;
        this.identityProvider = identityProvider;
    }

    ProxyResponse forward(ProxyConnection connection, String body, Map<String, String> incoming) {
        Map<String, String> credentials = isolatedCredentials(incoming);
        String version = identityVersion(incoming).orElseGet(() -> protocolVersion(connection));
        var exchange = new IsolatedExchange(connection, version);
        try {
            var session = new McpConnection(new McpFlow(BoundedBodyReader.MAX_RESPONSE_BYTES, MAX_FLOW_MESSAGES),
                    CredentialProviders.custom(credentials))
                    .openInitializeHttpSession(exchange::send, identityProvider.current().profile(), version);
            return proxyResponse(session.send(new McpRequests.Request(body,
                    Map.of(McpHeaders.PROTOCOL_VERSION, session.session().version()))));
        } catch (IllegalArgumentException | ConnectionAuthException failure) {
            return exchange.refusal().map(IsolatedHttpForwarder::proxyResponse).orElseThrow(() -> failure);
        } finally {
            deleteSessions(connection, credentials, exchange);
        }
    }

    ProxyResponse forwardInitialize(ProxyConnection connection, String body, Map<String, String> incoming) {
        Map<String, String> credentials = isolatedCredentials(incoming);
        var exchange = new IsolatedExchange(connection, protocolVersion(connection));
        try {
            return proxyResponse(exchange.send(new McpRequests.Request(body, credentials)));
        } finally {
            deleteSessions(connection, credentials, exchange);
        }
    }

    private static Map<String, String> isolatedCredentials(Map<String, String> incoming) {
        var headers = new HashMap<>(SentinelHeaders.withoutSentinels(incoming));
        headers.keySet().removeIf(name -> !ReservedHeaderPolicy.isForwardable(name) || McpHeaders.isProtocolHeader(name));
        return headers;
    }

    private static Optional<String> identityVersion(Map<String, String> incoming) {
        if (!SentinelHeaders.hasIdentity(incoming)) {
            return Optional.empty();
        }
        return incoming.entrySet().stream()
                .filter(header -> McpHeaders.PROTOCOL_VERSION.equalsIgnoreCase(header.getKey()))
                .map(Map.Entry::getValue)
                .filter(McpRequests::supportedHandshake)
                .findFirst();
    }

    private String protocolVersion(ProxyConnection connection) {
        String negotiated = guard.use(connection, scannerSession::negotiatedProtocolVersion);
        return negotiated != null ? negotiated
                : guard.use(connection, () -> headerValue(scannerSession.protocolHeaders(), McpHeaders.PROTOCOL_VERSION,
                        McpRequests.HANDSHAKE_VERSION));
    }

    private final class IsolatedExchange {
        private final ProxyConnection connection;
        private final String preferredVersion;
        private final AtomicReference<McpFlow.HttpResponse> last = new AtomicReference<>();
        private final Map<String, String> sessions = new HashMap<>();

        private IsolatedExchange(ProxyConnection connection, String preferredVersion) {
            this.connection = connection;
            this.preferredVersion = preferredVersion;
        }

        private McpFlow.HttpResponse send(McpRequests.Request framed) {
            var response = sendUpstream(framed);
            last.set(response);
            return response;
        }

        private Optional<McpFlow.HttpResponse> refusal() {
            return Optional.ofNullable(last.get()).filter(response -> UpstreamRefusal.isRefusal(response.status()));
        }

        private McpFlow.HttpResponse sendUpstream(McpRequests.Request framed) {
            String version = headerValue(framed.headers(), McpHeaders.PROTOCOL_VERSION, preferredVersion);
            framed.headers().forEach((name, value) -> {
                if (name.equalsIgnoreCase(McpHeaders.SESSION_ID)) sessions.put(value, version);
            });
            ProtocolHttpRequest request = guard.use(connection,
                    () -> requests.post(connection.endpoint(), framed.body(), framed.headers()));
            try (ProtocolHttpResponse response = upstream.send(request)) {
                response.firstHeader(McpHeaders.SESSION_ID).ifPresent(session -> sessions.put(session, version));
                return flowResponse(request, response, framed.body());
            } catch (IOException failure) {
                throw new UncheckedIOException(failure);
            } catch (InterruptedException failure) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Isolated HTTP request interrupted", failure);
            }
        }

        private McpFlow.HttpResponse flowResponse(ProtocolHttpRequest request, ProtocolHttpResponse response,
                                                  String requestBody) throws IOException {
            var converted = upstream.readReply(request, response, requestBody);
            guard.requireLive(connection);
            Map<String, String> headers = new HashMap<>();
            response.headers().forEach((name, values) -> headers.put(name, String.join(", ", values)));
            headers.keySet().removeIf("Content-Type"::equalsIgnoreCase);
            headers.put("Content-Type", converted.contentType());
            return new McpFlow.HttpResponse(converted.statusCode(), Map.copyOf(headers), converted.body(), true);
        }
    }

    private void deleteSessions(ProxyConnection connection, Map<String, String> credentials,
                                IsolatedExchange exchange) {
        exchange.sessions.forEach((session, selectedVersion) -> {
            if (!scannerSession.isIssuedSessionId(session)) {
                deleteSession(connection.endpoint(), credentials, session, selectedVersion);
            }
        });
    }

    private void deleteSession(String endpoint, Map<String, String> credentials, String session, String version) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(McpHeaders.PROTOCOL_VERSION, version);
        headers.put(McpHeaders.SESSION_ID, session);
        headers.putAll(credentials);
        try {
            upstream.send(new ProtocolHttpRequest(URI.create(endpoint), "DELETE", headers, null)).close();
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            scannerSession.eventLog().warn("Isolated HTTP session cleanup interrupted");
        } catch (IOException | RuntimeException failure) {
            scannerSession.eventLog().warn("Isolated HTTP session cleanup failed");
        }
    }

    private static String headerValue(Map<String, String> headers, String name, String fallback) {
        return headers.entrySet().stream()
                .filter(header -> header.getKey().equalsIgnoreCase(name))
                .map(Map.Entry::getValue).findFirst().orElse(fallback);
    }

    static ProxyResponse proxyResponse(McpFlow.HttpResponse response) {
        return new ProxyResponse(response.status(), response.headers().getOrDefault("Content-Type", "application/json"),
                response.body(), RelayedHeaders.of(response.headers()));
    }
}
