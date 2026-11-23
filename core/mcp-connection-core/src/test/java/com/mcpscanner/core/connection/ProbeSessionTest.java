package com.mcpscanner.core.connection;

import com.mcpscanner.core.protocol.McpFlow;
import com.mcpscanner.core.protocol.McpRequestId;
import com.mcpscanner.core.protocol.McpRequests;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

public final class ProbeSessionTest {
    private static final String VERSION = "2025-06-18";

    public static void main(String[] args) {
        httpProbeExposesTheIssuedSessionId();
        httpProbeNeverReinitializesOnSessionNotFound();
        httpProbeStillRecoversChallengedCredentials();
        httpProbeTerminatesWithDeleteAndReportsStatus();
        httpProbeTerminationRecoversChallengedCredentials();
        httpProbeKeepsSendingTheTerminatedSessionId();
        closingAnHttpProbeTerminatesItOnce();
        statelessHttpProbeHasNoSessionToTerminate();
        sseProbeExposesTheEndpointSessionId();
        sseProbeWithoutSessionParameterHasNoSessionId();
        sseProbeNeverReconnectsAfterItsStreamFails();
        sseProbeTerminationClosesTheStream();
        sseProbeReportsAChallengeInsteadOfReconnecting();
        failedHandshakeDeletesTheIssuedSession();
        failedHandshakeWithoutAnIssuedSessionDeletesNothing();
        failedHandshakeCleanupUsesTheNegotiatedVersion();
        failedCleanupIsSuppressedBehindTheHandshakeFailure();
        sseSessionIdIsDecodedWhereverItAppears();
        emptySseSessionIdIsNoSessionId();
        sseSessionIdIsAlsoAvailableAsSent();
        System.out.println("ProbeSessionTest passed");
    }

    private static void httpProbeExposesTheIssuedSessionId() {
        var server = new StatefulServer("issued-1");
        var probe = server.openProbe(CredentialProviders.none());
        equal(Optional.of("issued-1"), probe.sessionId());
        equal("issued-1", probe.session().sessionId());
    }

    private static void httpProbeNeverReinitializesOnSessionNotFound() {
        var server = new StatefulServer("issued-1");
        var probe = server.openProbe(CredentialProviders.none());
        server.forgetSessions();
        equal(404, probe.send(probe.session().operation("tools/list", "{}", 9)).status());
        equal(1, server.initializations.get());
        equal(Optional.of("issued-1"), probe.sessionId());
    }

    private static void httpProbeStillRecoversChallengedCredentials() {
        var server = new StatefulServer("issued-1");
        var refreshes = new AtomicInteger();
        var tokens = new ArrayDeque<>(List.of("old", "new"));
        var probe = server.openProbe(new RefreshingProvider(tokens, refreshes));
        server.requiredToken = "Bearer new";
        equal(200, probe.send(probe.session().operation("tools/list", "{}", 9)).status());
        equal(1, refreshes.get());
        equal(1, server.initializations.get());
    }

    private static void httpProbeTerminatesWithDeleteAndReportsStatus() {
        var server = new StatefulServer("issued-1");
        var probe = server.openProbe(CredentialProviders.bearer("token"));
        equal(204, probe.terminate().status());
        equal(1, server.deletions.size());
        var headers = server.deletions.get(0);
        equal("issued-1", headers.get("MCP-Session-Id"));
        equal(VERSION, headers.get("MCP-Protocol-Version"));
        equal("Bearer token", headers.get("Authorization"));
    }

    private static void httpProbeTerminationRecoversChallengedCredentials() {
        var server = new StatefulServer("issued-1");
        var refreshes = new AtomicInteger();
        var probe = server.openProbe(new RefreshingProvider(new ArrayDeque<>(List.of("old", "new")), refreshes));
        server.requiredToken = "Bearer new";
        equal(204, probe.terminate().status());
        equal(1, refreshes.get());
        equal(2, server.deletions.size());
    }

    private static void httpProbeKeepsSendingTheTerminatedSessionId() {
        var server = new StatefulServer("issued-1");
        var probe = server.openProbe(CredentialProviders.none());
        probe.terminate();
        equal(404, probe.send(probe.session().operation("tools/list", "{}", 9)).status());
        equal("issued-1", server.lastOperationSessionId);
        equal(1, server.initializations.get());
    }

    private static void closingAnHttpProbeTerminatesItOnce() {
        var server = new StatefulServer("issued-1");
        try (var probe = server.openProbe(CredentialProviders.none())) {
            probe.terminate();
        }
        equal(1, server.deletions.size());
        try (var probe = server.openProbe(CredentialProviders.none())) {
            equal(Optional.of("issued-1"), probe.sessionId());
        }
        equal(2, server.deletions.size());
    }

    private static void statelessHttpProbeHasNoSessionToTerminate() {
        var server = new StatefulServer(null);
        var probe = server.openProbe(CredentialProviders.none());
        equal(Optional.empty(), probe.sessionId());
        try {
            probe.terminate();
            throw new AssertionError("A stateless probe cannot be terminated");
        } catch (IllegalStateException expected) { }
        probe.close();
        equal(0, server.deletions.size());
    }

    private static void sseProbeExposesTheEndpointSessionId() {
        var server = new SseServer("/messages/?session_id=abc123");
        try (var probe = server.openProbe()) {
            equal(Optional.of("abc123"), probe.sessionId());
        }
        var typescript = new SseServer("/message?sessionId=ts-42");
        try (var probe = typescript.openProbe()) {
            equal(Optional.of("ts-42"), probe.sessionId());
        }
    }

    private static void sseProbeWithoutSessionParameterHasNoSessionId() {
        var server = new SseServer("/message");
        try (var probe = server.openProbe()) {
            equal(Optional.empty(), probe.sessionId());
        }
    }

    private static void sseProbeNeverReconnectsAfterItsStreamFails() {
        var server = new SseServer("/messages/?session_id=abc123");
        try (var probe = server.openProbe()) {
            server.postStatus = 404;
            expectFailure(() -> probe.call(probe.session().operation("tools/list", "{}", 9), McpRequestId.of(9)));
            server.postStatus = 202;
            expectFailure(() -> probe.call(probe.session().operation("tools/list", "{}", 10), McpRequestId.of(10)));
            equal(1, server.streams.get());
        }
    }

    private static void sseProbeTerminationClosesTheStream() {
        var server = new SseServer("/messages/?session_id=abc123");
        var probe = server.openProbe();
        probe.terminate();
        equal(1, server.closes.get());
        expectFailure(() -> probe.call(probe.session().operation("tools/list", "{}", 9), McpRequestId.of(9)));
        probe.close();
        equal(1, server.closes.get());
        equal(1, server.streams.get());
    }

    private static void sseProbeReportsAChallengeInsteadOfReconnecting() {
        var server = new SseServer("/messages/?session_id=abc123");
        var refreshes = new AtomicInteger();
        try (var probe = server.openProbe(new RefreshingProvider(new ArrayDeque<>(List.of("old", "new")), refreshes))) {
            server.postStatus = 401;
            try {
                probe.call(probe.session().operation("tools/list", "{}", 9), McpRequestId.of(9));
                throw new AssertionError("A challenged SSE probe must report the challenge");
            } catch (SseOpenException challenge) {
                equal(401, challenge.response().status());
            }
            equal(1, server.streams.get());
        }
    }

    private static void failedHandshakeDeletesTheIssuedSession() {
        var server = new StatefulServer("issued-1");
        server.initializedStatus = 500;
        expectFailure(() -> server.openProbe(CredentialProviders.bearer("token")));
        equal(1, server.deletions.size());
        equal("issued-1", server.deletions.get(0).get("MCP-Session-Id"));
        equal(VERSION, server.deletions.get(0).get("MCP-Protocol-Version"));
        equal("Bearer token", server.deletions.get(0).get("Authorization"));
    }

    private static void failedHandshakeWithoutAnIssuedSessionDeletesNothing() {
        var server = new StatefulServer(null);
        server.initializedStatus = 500;
        expectFailure(() -> server.openProbe(CredentialProviders.none()));
        equal(0, server.deletions.size());
    }

    private static void failedHandshakeCleanupUsesTheNegotiatedVersion() {
        var server = new StatefulServer("issued-1");
        server.negotiatedVersion = "2025-03-26";
        server.initializedStatus = 500;
        expectFailure(() -> server.openProbe(CredentialProviders.none()));
        equal("2025-03-26", server.deletions.get(0).get("MCP-Protocol-Version"));
    }

    private static void failedCleanupIsSuppressedBehindTheHandshakeFailure() {
        var server = new StatefulServer("issued-1");
        server.initializedStatus = 500;
        var cleanupFailure = new IllegalStateException("cleanup refused");
        try {
            new McpConnection(new McpFlow(8192, 10), CredentialProviders.none()).openInitializeHttpProbe(server::post,
                headers -> { throw cleanupFailure; }, "probe", "1", VERSION);
            throw new AssertionError("The handshake failure must be rethrown");
        } catch (IllegalArgumentException handshakeFailure) {
            equal(List.of(cleanupFailure), List.of(handshakeFailure.getSuppressed()));
        }
    }

    private static void sseSessionIdIsDecodedWhereverItAppears() {
        equal(Optional.of("a+b"), SseSessionIds.from("/messages/?x=1&session_id=a%2Bb"));
        equal(Optional.of("t s"), SseSessionIds.from("http://host/message?transport=sse&sessionId=t%20s"));
    }

    private static void sseSessionIdIsAlsoAvailableAsSent() {
        equal(Optional.of("a%2Bb%3D%3D"), SseSessionIds.sentFrom("/messages/?x=1&session_id=a%2Bb%3D%3D"));
        equal(Optional.empty(), SseSessionIds.sentFrom("/message?sessionId="));
    }

    private static void emptySseSessionIdIsNoSessionId() {
        equal(Optional.empty(), SseSessionIds.from("/message?sessionId="));
        equal(Optional.empty(), SseSessionIds.from("/messages/?other_session_id=x"));
    }

    private static final class StatefulServer {
        final AtomicInteger initializations = new AtomicInteger();
        final List<Map<String, String>> deletions = new ArrayList<>();
        final String issuedId;
        String requiredToken;
        String lastOperationSessionId;
        int initializedStatus = 202;
        String negotiatedVersion = VERSION;
        boolean known = true;

        StatefulServer(String issuedId) { this.issuedId = issuedId; }

        HttpProbeSession openProbe(CredentialProvider credentials) {
            return new McpConnection(new McpFlow(8192, 10), credentials)
                .openInitializeHttpProbe(this::post, this::delete, "probe", "1", VERSION);
        }

        void forgetSessions() { known = false; }

        McpFlow.HttpResponse post(McpRequests.Request request) {
            if (request.body().contains("\"initialize\"")) {
                initializations.incrementAndGet();
                Map<String, String> headers = issuedId == null ? Map.of() : Map.of("MCP-Session-Id", issuedId);
                return new McpFlow.HttpResponse(200, headers,
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"" + negotiatedVersion + "\"}}", true);
            }
            if (request.body().contains("notifications/initialized")) return reply(initializedStatus, "");
            if (challenged(request.headers())) return reply(401, "");
            lastOperationSessionId = request.headers().get("MCP-Session-Id");
            if (!known) return reply(404, "{\"jsonrpc\":\"2.0\",\"id\":\"server-error\",\"error\":{\"code\":-32001,\"message\":\"Session not found\"}}");
            return reply(200, "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"tools\":[]}}");
        }

        McpFlow.HttpResponse delete(Map<String, String> headers) {
            deletions.add(headers);
            if (challenged(headers)) return reply(401, "");
            known = false;
            return reply(204, "");
        }

        private boolean challenged(Map<String, String> headers) {
            return requiredToken != null && !requiredToken.equals(headers.get("Authorization"));
        }
    }

    private static final class SseServer {
        final AtomicInteger streams = new AtomicInteger();
        final AtomicInteger closes = new AtomicInteger();
        final String endpoint;
        int postStatus = 202;

        SseServer(String endpoint) { this.endpoint = endpoint; }

        SseProbeSession openProbe() {
            return openProbe(CredentialProviders.none());
        }

        SseProbeSession openProbe(CredentialProvider credentials) {
            return new McpConnection(new McpFlow(8192, 10), credentials)
                .openSseProbe(this::open, "https://fixture.example/sse", "probe", "1");
        }

        SseStreamFactory.Stream open(Map<String, String> headers) {
            streams.incrementAndGet();
            var events = new ArrayDeque<String>();
            events.add("event: endpoint\ndata: " + endpoint + "\n\n");
            events.add("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2024-11-05\"}}\n\n");
            return new SseStreamFactory.Stream() {
                public String nextEvent() { return events.poll(); }
                public McpFlow.HttpResponse post(String target, McpRequests.Request request) {
                    if (request.body().contains("\"initialize\"") || request.body().contains("notifications/initialized"))
                        return reply(202, "");
                    events.add("data: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}\n\n");
                    return reply(postStatus, "");
                }
                public void close() { closes.incrementAndGet(); }
            };
        }
    }

    private static final class RefreshingProvider implements CredentialProvider {
        private final ArrayDeque<String> tokens;
        private final AtomicInteger refreshes;

        RefreshingProvider(ArrayDeque<String> tokens, AtomicInteger refreshes) {
            this.tokens = tokens;
            this.refreshes = refreshes;
        }

        public Map<String, String> headers() { return Map.of("Authorization", "Bearer " + tokens.peek()); }

        public OperationRecovery beginOperation(String operation) {
            return response -> {
                if (tokens.size() < 2) return RecoveryResult.STOP;
                tokens.poll();
                refreshes.incrementAndGet();
                return RecoveryResult.RETRY;
            };
        }
    }

    private static McpFlow.HttpResponse reply(int status, String body) {
        return new McpFlow.HttpResponse(status, Map.of(), body, true);
    }

    private static void expectFailure(Runnable operation) {
        try {
            operation.run();
        } catch (RuntimeException expected) {
            return;
        }
        throw new AssertionError("Expected the probe operation to fail");
    }

    private static void equal(Object expected, Object actual) {
        if (!java.util.Objects.equals(expected, actual))
            throw new AssertionError("Expected " + expected + " but got " + actual);
    }
}
