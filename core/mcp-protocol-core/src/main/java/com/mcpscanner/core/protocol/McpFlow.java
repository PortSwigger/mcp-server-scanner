package com.mcpscanner.core.protocol;

public final class McpFlow {
    public record HttpResponse(int status, java.util.Map<String, String> headers, String body, boolean complete) {
        public boolean successful() { return status >= 200 && status < 300 && complete; }
    }
    public interface HttpPort { HttpResponse send(McpRequests.Request request); }
    public interface SsePort extends McpEventSource {
        HttpResponse post(String endpoint, McpRequests.Request request);
    }
    public record Session(String version, String sessionId, String endpoint, ClientProfile client) {
        public Session(String version, String sessionId, String endpoint, String clientName, String clientVersion) {
            this(version, sessionId, endpoint, ClientProfile.of(clientName, clientVersion));
        }

        public String clientName() { return client.name(); }

        public String clientVersion() { return client.version(); }

        public McpRequests.Request request(String method, String cursor) {
            return request(method, cursor, 1);
        }

        public McpRequests.Request request(String method, String cursor, long id) {
            if (McpRequests.MODERN_VERSION.equals(version))
                return McpRequests.modern(method, client, cursor, id);
            return McpRequests.catalog(method, version, sessionId, cursor, id);
        }

        public McpRequests.Request response(McpRequestId id, String result) {
            return McpRequests.response(version, sessionId, id, result);
        }

        public McpRequests.Request notification(String method, String params) {
            return McpRequests.notification(method, params, version, sessionId, client);
        }

        public McpRequests.Request operation(String method, String params) {
            return operation(method, params, 1);
        }

        public McpRequests.Request operation(String method, String params, long id) {
            return operation(method, params, McpRequestId.of(id));
        }

        public McpRequests.Request operation(String method, String params, McpRequestId id) {
            if (McpRequests.MODERN_VERSION.equals(version))
                return McpRequests.modernOperation(method, client, params, id);
            return McpRequests.httpPost(method, version, sessionId, params, id);
        }
    }

    private final int maxBytes;
    private final int maxEvents;

    public McpFlow(int maxBytes, int maxEvents) {
        if (maxBytes <= 0 || maxEvents <= 0) throw new IllegalArgumentException("positive bounds required");
        this.maxBytes = maxBytes;
        this.maxEvents = maxEvents;
    }

    public Session openHttp(HttpPort port, String clientName, String clientVersion) {
        return openHttp(port, ClientProfile.of(clientName, clientVersion));
    }

    public Session openHttp(HttpPort port, ClientProfile client) {
        Session modern = tryOpenModernHttp(port, client);
        return modern != null ? modern : openInitializeHttp(port, client, McpRequests.HANDSHAKE_VERSION);
    }

    public Session openModernHttp(HttpPort port, String clientName, String clientVersion) {
        return openModernHttp(port, ClientProfile.of(clientName, clientVersion));
    }

    public Session openModernHttp(HttpPort port, ClientProfile client) {
        Session modern = tryOpenModernHttp(port, client);
        if (modern == null) throw new IllegalArgumentException("server/discover failed");
        return modern;
    }

    private Session tryOpenModernHttp(HttpPort port, ClientProfile client) {
        HttpResponse modern = port.send(McpRequests.modern("server/discover", client, null));
        if (modern != null && modern.complete() && modern.status() == 400) {
            try {
                if (McpResponses.modernCounterOffer(responseReply(modern, 1)))
                    modern = port.send(McpRequests.modern("server/discover", client, null));
            } catch (IllegalArgumentException invalid) { }
        }
        if (modern != null && modern.successful()) {
            try {
                McpResponses.Reply reply = responseReply(modern, 1);
                if (McpResponses.modernDiscovery(reply))
                    return new Session(McpRequests.MODERN_VERSION, null, null, client);
            } catch (IllegalArgumentException invalid) { }
        }
        return null;
    }

    public Session openInitializeHttp(HttpPort port, String clientName, String clientVersion, String preferredVersion) {
        return openInitializeHttp(port, ClientProfile.of(clientName, clientVersion), preferredVersion);
    }

    public Session openInitializeHttp(HttpPort port, ClientProfile client, String preferredVersion) {
        if (!McpRequests.supportedHandshake(preferredVersion))
            throw new IllegalArgumentException("preferred protocolVersion " + preferredVersion
                + " is not a supported initialize version");
        String version = preferredVersion;
        HttpResponse admission = port.send(McpRequests.initialize(version, client));
        var offeredVersions = new java.util.HashSet<>(java.util.Set.of(version));
        for (String counter = counterOffer(admission); counter != null && offeredVersions.add(counter);
                counter = counterOffer(admission)) {
            version = counter;
            admission = port.send(McpRequests.initialize(version, client));
        }
        requireSuccess(admission, "initialize offering protocolVersion " + version);
        McpResponses.Session selected = McpResponses.negotiate(responseReply(admission, 1),
            version, admission.headers());
        requireSuccess(port.send(McpRequests.initialized(selected.version(), selected.sessionId())),
            "notifications/initialized for protocolVersion " + selected.version());
        return new Session(selected.version(), selected.sessionId(), null, client);
    }

    private String counterOffer(HttpResponse admission) {
        if (admission == null || !admission.complete() || admission.status() != 400) return null;
        return eventStream(admission)
            ? McpResponses.counterOffer(responseReply(admission, 1))
            : McpResponses.counterOffer(admission.body(), maxBytes);
    }

    private static void requireSuccess(HttpResponse response, String stage) {
        if (response == null) throw new IllegalArgumentException(stage + " failed: no response");
        if (!response.successful()) throw new HandshakeRefusedException(stage, response.status(), response.complete());
    }

    private McpResponses.Reply responseReply(HttpResponse response, long expectedId) {
        return codec().parse(response, expectedId);
    }

    private McpReplyCodec codec() {
        return new McpReplyCodec(maxBytes, maxEvents);
    }

    private boolean eventStream(HttpResponse response) {
        return McpReplyCodec.eventStream(response);
    }

    public Session openSse(SsePort port, String origin, String clientName, String clientVersion) {
        return openSse(port, origin, ClientProfile.of(clientName, clientVersion));
    }

    public Session openSse(SsePort port, String origin, ClientProfile client) {
        return openSse(port, origin, client, session -> ServerRequestHandler.disabled());
    }

    private static ServerRequestHandler handlerFor(java.util.function.Function<Session, ServerRequestHandler> handlers,
                                                   Session session) {
        return java.util.Objects.requireNonNullElse(handlers.apply(session), ServerRequestHandler.disabled());
    }

    public Session openSse(SsePort port, String origin, ClientProfile client,
                           java.util.function.Function<Session, ServerRequestHandler> handlers) {
        String endpoint = awaitEndpoint(port, origin);
        requireSuccess(port.post(endpoint, McpRequests.initialize(McpRequests.SSE_VERSION, client)),
            "SSE initialize offering protocolVersion " + McpRequests.SSE_VERSION);
        Session handshake = new Session(McpRequests.SSE_VERSION, null, endpoint, client);
        McpResponses.Reply reply = awaitSseReply(port, handshake, McpRequestId.of(1), handlerFor(handlers, handshake)).numeric();
        McpResponses.Session selected = McpResponses.negotiate(reply, McpRequests.SSE_VERSION, java.util.Map.of());
        requireSuccess(port.post(endpoint, McpRequests.initialized(selected.version(), null)),
            "SSE notifications/initialized for protocolVersion " + selected.version());
        return new Session(selected.version(), null, endpoint, client);
    }

    private String awaitEndpoint(SsePort port, String origin) {
        for (int i = 0; i < maxEvents; i++) {
            String event = port.nextEvent();
            if (event == null) throw new IllegalArgumentException("SSE closed before endpoint");
            if (McpSse.isEndpoint(event, maxBytes)) return McpSse.endpoint(origin, event, maxBytes);
        }
        throw new IllegalArgumentException("SSE endpoint event limit");
    }

    private McpResponses.GenericReply awaitSseReply(SsePort port, Session session, McpRequestId expectedId,
                                                    ServerRequestHandler handler) {
        return codec().read(port, expectedId, handler, reply -> port.post(session.endpoint(), reply));
    }

    public McpResponses.Reply callSse(SsePort port, Session session, McpRequests.Request request, long expectedId) {
        return callSse(port, session, request, McpRequestId.of(expectedId)).numeric();
    }

    public McpResponses.GenericReply callSse(SsePort port, Session session, McpRequests.Request request, McpRequestId expectedId) {
        return callSse(port, session, request, expectedId, ServerRequestHandler.disabled());
    }

    public McpResponses.GenericReply callSse(SsePort port, Session session, McpRequests.Request request,
                                             McpRequestId expectedId, ServerRequestHandler handler) {
        if (port == null || session == null || session.endpoint() == null || request == null)
            throw new IllegalArgumentException("open SSE session with an SSE endpoint required");
        HttpResponse posted = port.post(session.endpoint(), request);
        if (posted == null || !posted.successful()) throw new IllegalArgumentException("SSE request POST failed");
        return awaitSseReply(port, session, expectedId, handler);
    }
}
