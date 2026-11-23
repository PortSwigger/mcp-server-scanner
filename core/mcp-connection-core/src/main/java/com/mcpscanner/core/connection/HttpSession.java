package com.mcpscanner.core.connection;

import com.mcpscanner.core.protocol.JsonDocuments;
import com.mcpscanner.core.protocol.McpFlow;
import com.mcpscanner.core.protocol.McpRequestId;
import com.mcpscanner.core.protocol.McpRequests;
import com.mcpscanner.core.protocol.McpResponses;

public final class HttpSession {
    private static final int MAX_EXPIRY_BODY_BYTES = 64 * 1024;
    private final McpConnection connection;
    private final McpFlow flow;
    private final McpFlow.HttpPort port;
    private final SessionExpiry expiry;
    private final Object reinitialization = new Object();
    private McpFlow.Session session;

    HttpSession(McpConnection connection, McpFlow flow, McpFlow.HttpPort port, McpFlow.Session session) {
        this(connection, flow, port, session, SessionExpiry.REINITIALIZE);
    }

    HttpSession(McpConnection connection, McpFlow flow, McpFlow.HttpPort port, McpFlow.Session session,
                SessionExpiry expiry) {
        this.connection = connection;
        this.flow = flow;
        this.port = port;
        this.session = session;
        this.expiry = expiry;
    }

    public synchronized McpFlow.Session session() { return session; }

    private synchronized void replaceSession(McpFlow.Session selected) { session = selected; }

    public McpFlow.HttpResponse send(McpRequests.Request request) {
        var recovery = connection.beginRecovery();
        boolean reinitialized = false;
        var sentSession = session();
        var currentRequest = withSession(request, sentSession);
        for (int attempt = 0; ; attempt++) {
            var response = port.send(connection.authenticate(currentRequest));
            if (attempt == 2 || response == null || !response.complete()) return response;
            if (connection.challenged(response)) {
                if (!connection.recover(recovery, response)) return response;
            } else if (!reinitialized && expiry == SessionExpiry.REINITIALIZE
                    && missingSession(sentSession, currentRequest, response)) {
                sentSession = reinitializeOnce(sentSession, recovery);
                reinitialized = true;
                currentRequest = withSession(request, sentSession);
            } else return response;
        }
    }

    private boolean missingSession(McpFlow.Session sentSession, McpRequests.Request request, McpFlow.HttpResponse response) {
        return response.status() == 404 && sentSession.sessionId() != null
            && !McpRequests.MODERN_VERSION.equals(sentSession.version())
            && carriesSessionVersion(sentSession, request) && !answersRequest(request, response);
    }

    private static boolean carriesSessionVersion(McpFlow.Session sentSession, McpRequests.Request request) {
        return Headers.first(request.headers(), "MCP-Protocol-Version")
            .map(sentSession.version()::equals).orElse(true);
    }

    private static boolean answersRequest(McpRequests.Request request, McpFlow.HttpResponse response) {
        try {
            var reply = McpResponses.parseGenericAllowingNullErrorId(response.body(), MAX_EXPIRY_BODY_BYTES);
            return reply.id() != null && reply.id().equals(requestId(request));
        } catch (IllegalArgumentException notAReply) {
            return false;
        }
    }

    private static McpRequestId requestId(McpRequests.Request request) {
        int size = request.body().getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        return JsonDocuments.parse(request.body(), size) instanceof java.util.Map<?, ?> document
            && document.get("id") != null ? McpRequestId.of(document.get("id")) : null;
    }

    private McpFlow.Session reinitializeOnce(McpFlow.Session expired, OperationRecovery recovery) {
        synchronized (reinitialization) {
            var current = session();
            if (current != expired) return current;
            var selected = reinitialize(expired, recovery);
            replaceSession(selected);
            return selected;
        }
    }

    private McpFlow.Session reinitialize(McpFlow.Session expired, OperationRecovery recovery) {
        String version = expired.version();
        var selected = flow.openInitializeHttp(request -> {
            if (Headers.first(request.headers(), "MCP-Protocol-Version").filter(sent -> !version.equals(sent)).isPresent())
                throw new IllegalArgumentException("Session recovery cannot change protocol version");
            return sendHandshake(request, recovery);
        }, expired.client(), version);
        if (!version.equals(selected.version())) throw new IllegalArgumentException("Session recovery cannot change protocol version");
        return selected;
    }

    private McpFlow.HttpResponse sendHandshake(McpRequests.Request request, OperationRecovery recovery) {
        for (int attempt = 0; ; attempt++) {
            var response = port.send(connection.authenticate(request));
            if (!connection.challenged(response)) return response;
            if (attempt == 2 || !connection.recover(recovery, response))
                throw new ConnectionAuthException(RecoveryResult.STOP);
        }
    }

    private static McpRequests.Request withSession(McpRequests.Request request, McpFlow.Session session) {
        var headers = new java.util.LinkedHashMap<>(request.headers());
        headers.keySet().removeIf(name -> name.equalsIgnoreCase("MCP-Session-Id"));
        if (session.sessionId() != null) headers.put("MCP-Session-Id", session.sessionId());
        return new McpRequests.Request(request.body(), java.util.Map.copyOf(headers));
    }
}
