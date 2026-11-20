package com.mcpscanner.core.connection;

import com.mcpscanner.core.protocol.ClientInfo;
import com.mcpscanner.core.protocol.ClientProfile;
import com.mcpscanner.core.protocol.McpFlow;
import com.mcpscanner.core.protocol.McpRequests;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public final class HttpSessionTest {
    public static void main(String[] args) {
        fixedLegacySessionsRecoverWithinTheirIdentityAndVersion();
        fullClientProfileSurvivesReinitialization();
        expiredLegacySessionRecoversWithoutAuthChallenge();
        reinitializationRefreshesChallengedCredentials();
        reinitializationRequestsScopeApproval();
        reinitializationHonorsScopeDenial();
        reinitializationCannotRefreshTwice();
        anonymousReinitializationNeverUsesCredentials();
        reinitializationSharesOriginalAuthRecoveryBudget();
        replyToSentRequestNeverReinitializes();
        stringIdReplyToSentRequestNeverReinitializes();
        sdkSessionNotFoundBodiesReinitialize();
        batchRequestExpiryReinitializes();
        standaloneRepeatedExpiryIsBounded();
        statelessLegacy404NeverReinitializes();
        modern404NeverReinitializes();
        fuzzedProtocolVersion404NeverReinitializes();
        sessionVersion404StillReinitializes();
        unversioned404StillReinitializes();
        refreshRecoversExpiredLegacySession();
        recoveryCanReplaceExpiredSessionWithStatelessSession();
        ambiguousResponsesNeverReplay();
        repeatedExpiryIsBounded();
        sessionRecoveryCannotDowngradeProtocol();
        concurrentSendsShareTheSessionWithoutWaitingForEachOther();
        concurrentExpiryReinitializesOnce();
        System.out.println("HttpSessionTest passed");
    }

    private static void fullClientProfileSurvivesReinitialization() {
        var initializations = new AtomicInteger();
        var profile = new ClientProfile(new ClientInfo("full", "2", "Full Title", null, "https://full.test", null), "{\"roots\":{}}");
        var connection = new McpConnection(new McpFlow(8192, 10), CredentialProviders.none());
        var session = connection.openInitializeHttpSession(request -> {
            if (request.body().contains("\"initialize\"")) {
                equal(true, request.body().contains("\"title\":\"Full Title\""));
                equal(true, request.body().contains("\"websiteUrl\":\"https://full.test\""));
                equal(true, request.body().contains("\"capabilities\":{\"roots\":{}}"));
                int generation = initializations.incrementAndGet();
                return new McpFlow.HttpResponse(200, Map.of("MCP-Session-Id", "s" + generation),
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\"}}", true);
            }
            if (request.body().contains("notifications/initialized")) return new McpFlow.HttpResponse(202, Map.of(), "", true);
            if (initializations.get() == 1) return new McpFlow.HttpResponse(404, Map.of(), "Session expired", true);
            return new McpFlow.HttpResponse(200, Map.of(), "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}", true);
        }, profile, "2025-06-18");
        session.send(session.session().operation("tools/list", "{}", 9));
        equal(2, initializations.get());
    }

    private static void fuzzedProtocolVersion404NeverReinitializes() {
        var server = new UnknownVersionRejectingServer("2025-06-18");
        var session = server.openSession();
        var probe = withHeader(session.session().operation("tools/call", "{}", 9), "mcp-protocol-version", "1999-01-01");
        equal(404, session.send(probe).status());
        equal(1, server.initializations.get());
        equal("s1", session.session().sessionId());
    }

    private static void sessionVersion404StillReinitializes() {
        var server = new UnknownVersionRejectingServer("2025-06-18");
        var session = server.openSession();
        server.expireSessions();
        equal(200, session.send(session.session().operation("tools/call", "{}", 9)).status());
        equal(2, server.initializations.get());
        equal("s2", session.session().sessionId());
    }

    private static void unversioned404StillReinitializes() {
        var server = new UnknownVersionRejectingServer("2025-06-18");
        var session = server.openSession();
        server.expireSessions();
        var unversioned = withoutHeader(session.session().operation("tools/call", "{}", 9), "MCP-Protocol-Version");
        equal(200, session.send(unversioned).status());
        equal(2, server.initializations.get());
        equal("s2", session.session().sessionId());
    }

    private static McpRequests.Request withoutHeader(McpRequests.Request request, String name) {
        var headers = new java.util.LinkedHashMap<>(request.headers());
        headers.keySet().removeIf(name::equalsIgnoreCase);
        return new McpRequests.Request(request.body(), headers);
    }

    private static McpRequests.Request withHeader(McpRequests.Request request, String name, String value) {
        var headers = new java.util.LinkedHashMap<>(withoutHeader(request, name).headers());
        headers.put(name, value);
        return new McpRequests.Request(request.body(), headers);
    }

    private static final class UnknownVersionRejectingServer {
        private final String version;
        private final AtomicInteger initializations = new AtomicInteger();
        private volatile String liveSession;

        private UnknownVersionRejectingServer(String version) {
            this.version = version;
        }

        private HttpSession openSession() {
            var connection = new McpConnection(new McpFlow(8192, 10), CredentialProviders.none());
            return connection.openInitializeHttpSession(this::send,
                new ClientProfile(new ClientInfo("fixture", "1", null, null, null, null), "{}"), version);
        }

        private void expireSessions() {
            liveSession = null;
        }

        private McpFlow.HttpResponse send(McpRequests.Request request) {
            if (request.body().contains("\"initialize\"")) {
                liveSession = "s" + initializations.incrementAndGet();
                return new McpFlow.HttpResponse(200, Map.of("MCP-Session-Id", liveSession),
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"" + version + "\"}}", true);
            }
            if (request.body().contains("notifications/initialized")) return new McpFlow.HttpResponse(202, Map.of(), "", true);
            boolean knownVersion = Headers.first(request.headers(), "MCP-Protocol-Version").map(version::equals).orElse(true);
            boolean liveSessionId = Headers.first(request.headers(), "MCP-Session-Id").filter(id -> id.equals(liveSession)).isPresent();
            if (!knownVersion || !liveSessionId) return new McpFlow.HttpResponse(404, Map.of(), "Not Found", true);
            return new McpFlow.HttpResponse(200, Map.of(), "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}", true);
        }
    }

    private static void fixedLegacySessionsRecoverWithinTheirIdentityAndVersion() {
        for (String version : java.util.List.of("2025-03-26", "2025-06-18", "2025-11-25")) {
            for (boolean authenticated : java.util.List.of(false, true)) {
                var initializations = new AtomicInteger();
                var notifications = new AtomicInteger();
                var operations = new AtomicInteger();
                var credentials = authenticated ? CredentialProviders.bearer("identity-b") : CredentialProviders.none();
                var connection = new McpConnection(new McpFlow(8192, 10), credentials);
                var session = connection.openInitializeHttpSession(request -> {
                    equal(authenticated ? "Bearer identity-b" : null, request.headers().get("Authorization"));
                    if (request.body().contains("server/discover"))
                        throw new AssertionError("Fixed legacy HTTP must never probe modern HTTP");
                    if (request.body().contains("\"initialize\"")) {
                        equal(true, request.body().contains("\"protocolVersion\":\"" + version + "\""));
                        equal(true, request.body().contains("\"name\":\"identity-fixture\""));
                        int generation = initializations.incrementAndGet();
                        return new McpFlow.HttpResponse(200, Map.of("MCP-Session-Id", "identity-session-" + generation),
                            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"" + version + "\"}}", true);
                    }
                    equal(version, request.headers().get("MCP-Protocol-Version"));
                    equal("identity-session-" + initializations.get(), request.headers().get("MCP-Session-Id"));
                    if (request.body().contains("notifications/initialized")) {
                        notifications.incrementAndGet();
                        return new McpFlow.HttpResponse(202, Map.of(), "", true);
                    }
                    equal(initializations.get(), notifications.get());
                    if (operations.incrementAndGet() == 1)
                        return new McpFlow.HttpResponse(404, Map.of(), "Session expired", true);
                    return new McpFlow.HttpResponse(200, Map.of(),
                        "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"tools\":[]}}", true);
                }, "identity-fixture", "1", version);
                equal(200, session.send(session.session().operation("tools/list", "{}", 9)).status());
                equal(version, session.session().version());
                equal("identity-session-2", session.session().sessionId());
                equal("identity-fixture", session.session().clientName());
                equal("1", session.session().clientVersion());
                equal(2, initializations.get());
                equal(2, notifications.get());
                equal(2, operations.get());
            }
        }
    }

    private static void expiredLegacySessionRecoversWithoutAuthChallenge() {
        var fixture = new Fixture();
        fixture.requireRefresh = false;
        var session = fixture.connection.openHttpSession(fixture::send, "fixture", "1");
        equal(200, session.send(session.session().operation("tools/call", "{}", 9)).status());
        equal("session-2", session.session().sessionId());
        equal("2025-11-25", session.session().version());
        equal("fixture", session.session().clientName());
        equal("1", session.session().clientVersion());
        equal(0, fixture.refreshes.get());
        equal(1, fixture.modernProbes.get());
        equal(2, fixture.initializations.get());
        equal(2, fixture.operations.get());
    }

    private static void reinitializationRefreshesChallengedCredentials() {
        var fixture = new HandshakeChallengeFixture(401);
        var session = fixture.open();
        equal(200, session.send(session.session().operation("tools/call", "{}", 9)).status());
        equal(1, fixture.refreshes);
        equal(3, fixture.initializations);
        equal(2, fixture.operations);
        equal("session-recovered", session.session().sessionId());
        equal("2025-11-25", session.session().version());
    }

    private static void reinitializationRequestsScopeApproval() {
        var fixture = new HandshakeChallengeFixture(403);
        fixture.approval = com.mcpscanner.core.oauth.AuthorizationApproval.APPROVED;
        var session = fixture.open();
        equal(200, session.send(session.session().operation("tools/call", "{}", 9)).status());
        equal(1, fixture.approvals);
        equal(1, fixture.authorizations);
        equal(0, fixture.refreshes);
        equal(3, fixture.initializations);
        equal(2, fixture.operations);
        equal("session-recovered", session.session().sessionId());
        equal("2025-11-25", session.session().version());
    }

    private static void reinitializationHonorsScopeDenial() {
        var fixture = new HandshakeChallengeFixture(403);
        fixture.approval = com.mcpscanner.core.oauth.AuthorizationApproval.DENIED;
        var session = fixture.open();
        try {
            session.send(session.session().operation("tools/call", "{}", 9));
            throw new AssertionError("Denied scopes must stop reinitialization");
        } catch (ConnectionAuthException expected) {
            equal(RecoveryResult.DENIED, expected.result());
            equal("Connection authentication requires attention: DENIED", expected.getMessage());
        }
        equal(1, fixture.approvals);
        equal(0, fixture.authorizations);
        equal(0, fixture.refreshes);
        equal(2, fixture.initializations);
        equal(1, fixture.operations);
        equal("session-old", session.session().sessionId());
    }

    private static void reinitializationCannotRefreshTwice() {
        var fixture = new HandshakeChallengeFixture(401);
        fixture.alwaysChallenge = true;
        fixture.approval = com.mcpscanner.core.oauth.AuthorizationApproval.APPROVED;
        var session = fixture.open();
        try {
            session.send(session.session().operation("tools/call", "{}", 9));
            throw new AssertionError("Repeated auth challenge must stop reinitialization");
        } catch (ConnectionAuthException expected) {
            equal(RecoveryResult.STOP, expected.result());
            equal("Connection authentication requires attention: STOP", expected.getMessage());
        }
        equal(1, fixture.refreshes);
        equal(1, fixture.authorizations);
        equal(1, fixture.approvals);
        equal(4, fixture.initializations);
        equal(1, fixture.operations);
        equal("session-old", session.session().sessionId());
    }

    private static void reinitializationSharesOriginalAuthRecoveryBudget() {
        var fixture = new HandshakeChallengeFixture(401);
        fixture.challengeOperation = true;
        fixture.alwaysChallenge = true;
        fixture.approval = com.mcpscanner.core.oauth.AuthorizationApproval.APPROVED;
        var session = fixture.open();
        try {
            session.send(session.session().operation("tools/call", "{}", 9));
            throw new AssertionError("Handshake must share original operation recovery budget");
        } catch (ConnectionAuthException expected) {
            equal(RecoveryResult.STOP, expected.result());
        }
        equal(1, fixture.refreshes);
        equal(1, fixture.authorizations);
        equal(1, fixture.approvals);
        equal(3, fixture.initializations);
        equal(2, fixture.operations);
        equal("session-old", session.session().sessionId());
    }

    private static void anonymousReinitializationNeverUsesCredentials() {
        var fixture = new HandshakeChallengeFixture(401);
        fixture.anonymous = true;
        var session = fixture.connection.anonymous().openHttpSession(fixture::send, "fixture", "1");
        try {
            session.send(session.session().operation("tools/call", "{}", 9));
            throw new AssertionError("Anonymous challenge must stop reinitialization");
        } catch (ConnectionAuthException expected) {
            equal(RecoveryResult.STOP, expected.result());
        }
        equal(0, fixture.credentialReads);
        equal(0, fixture.refreshes);
        equal(0, fixture.authorizations);
        equal(0, fixture.approvals);
        equal(2, fixture.initializations);
        equal(1, fixture.operations);
    }

    private static void replyToSentRequestNeverReinitializes() {
        var fixture = new Fixture();
        fixture.requireRefresh = false;
        fixture.expiredResponse = new McpFlow.HttpResponse(404, Map.of(),
            "{\"jsonrpc\":\"2.0\",\"id\":9,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}", true);
        var session = fixture.connection.openHttpSession(fixture::send, "fixture", "1");
        equal(fixture.expiredResponse, session.send(session.session().operation("unknown", "{}", 9)));
        equal(1, fixture.initializations.get());
        equal(1, fixture.operations.get());
        equal(0, fixture.refreshes.get());
    }

    private static void stringIdReplyToSentRequestNeverReinitializes() {
        for (String version : java.util.List.of("2025-03-26", "2025-06-18", "2025-11-25")) {
            var initializations = new AtomicInteger();
            var operations = new AtomicInteger();
            var response = new McpFlow.HttpResponse(404, Map.of(),
                "{\"jsonrpc\":\"2.0\",\"id\":\"operation-😀\",\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}", true);
            var connection = new McpConnection(new McpFlow(8192, 10), CredentialProviders.none());
            var session = connection.openInitializeHttpSession(request -> {
                if (request.body().contains("\"initialize\"")) {
                    initializations.incrementAndGet();
                    return new McpFlow.HttpResponse(200, Map.of("Mcp-Session-Id", "session-1"),
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"" + version + "\"}}", true);
                }
                if (request.body().contains("notifications/initialized"))
                    return new McpFlow.HttpResponse(202, Map.of(), "", true);
                operations.incrementAndGet();
                return response;
            }, "fixture", "1", version);
            var requestId = com.mcpscanner.core.protocol.McpRequestId.of("operation-😀");
            equal(response, session.send(session.session().operation("unknown", "{}", requestId)));
            equal(1, initializations.get());
            equal(1, operations.get());
        }
    }

    private static void batchRequestExpiryReinitializes() {
        var initializations = new AtomicInteger();
        var connection = new McpConnection(new McpFlow(8192, 10), CredentialProviders.none());
        var session = connection.openInitializeHttpSession(request -> {
            if (request.body().contains("\"initialize\"")) {
                int generation = initializations.incrementAndGet();
                return new McpFlow.HttpResponse(200, Map.of("MCP-Session-Id", "s" + generation),
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\"}}", true);
            }
            if (request.body().contains("notifications/initialized")) return new McpFlow.HttpResponse(202, Map.of(), "", true);
            if (initializations.get() == 1) return new McpFlow.HttpResponse(404, Map.of(),
                "{\"jsonrpc\":\"2.0\",\"id\":\"server-error\",\"error\":{\"code\":-32600,\"message\":\"Session not found\"}}", true);
            return new McpFlow.HttpResponse(200, Map.of(), "[]", true);
        }, ClientProfile.of("client", "1"), "2025-06-18");
        var batch = new com.mcpscanner.core.protocol.McpRequests.Request("[{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}]",
            session.session().operation("ping", "{}", 3).headers());
        session.send(batch);
        equal(2, initializations.get());
    }

    private static void sdkSessionNotFoundBodiesReinitialize() {
        for (String body : java.util.List.of(
                "{\"jsonrpc\":\"2.0\",\"id\":\"server-error\",\"error\":{\"code\":-32600,\"message\":\"Session not found\"}}",
                "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32001,\"message\":\"Session not found\"},\"id\":null}",
                "{\"jsonrpc\":\"2.0\",\"id\":8,\"error\":{\"code\":-32600,\"message\":\"Session not found\"}}")) {
            var fixture = new Fixture();
            fixture.requireRefresh = false;
            fixture.expiredResponse = new McpFlow.HttpResponse(404, Map.of("Content-Type", "application/json"), body, true);
            var session = fixture.connection.openHttpSession(fixture::send, "fixture", "1");
            equal(200, session.send(session.session().operation("tools/call", "{}", 9)).status());
            equal("session-2", session.session().sessionId());
            equal(2, fixture.initializations.get());
            equal(2, fixture.operations.get());
        }
    }

    private static void standaloneRepeatedExpiryIsBounded() {
        var fixture = new Fixture();
        fixture.requireRefresh = false;
        fixture.alwaysExpired = true;
        var session = fixture.connection.openHttpSession(fixture::send, "fixture", "1");
        equal(404, session.send(session.session().operation("tools/call", "{}", 9)).status());
        equal(2, fixture.initializations.get());
        equal(2, fixture.operations.get());
        equal(0, fixture.refreshes.get());
    }

    private static void statelessLegacy404NeverReinitializes() {
        var fixture = new Fixture();
        fixture.requireRefresh = false;
        fixture.statelessInitial = true;
        fixture.alwaysExpired = true;
        var session = fixture.connection.openHttpSession(fixture::send, "fixture", "1");
        equal(404, session.send(session.session().operation("tools/call", "{}", 9)).status());
        equal(1, fixture.initializations.get());
        equal(1, fixture.operations.get());
        equal(0, fixture.refreshes.get());
    }

    private static void modern404NeverReinitializes() {
        var operations = new AtomicInteger();
        var connection = new McpConnection(new McpFlow(8192, 10), CredentialProviders.none());
        var session = connection.openHttpSession(request -> {
            if (request.body().contains("server/discover"))
                return new McpFlow.HttpResponse(200, Map.of(),
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"capabilities\":{},\"supportedVersions\":[\"2026-07-28\"]}}", true);
            if (request.body().contains("\"initialize\"")) throw new AssertionError("Modern 404 must not initialize");
            operations.incrementAndGet();
            return new McpFlow.HttpResponse(404, Map.of(), "", true);
        }, "fixture", "1");
        equal(404, session.send(session.session().operation("tools/call", "{\"name\":\"tool\",\"arguments\":{}}", 9)).status());
        equal(1, operations.get());
    }

    private static void refreshRecoversExpiredLegacySession() {
        var fixture = new Fixture();
        var session = fixture.connection.openHttpSession(fixture::send, "fixture", "1");
        equal(200, session.send(session.session().operation("tools/call", "{}", 9)).status());
        equal("session-2", session.session().sessionId());
        equal(1, fixture.refreshes.get());
        equal(1, fixture.modernProbes.get());
        equal(2, fixture.initializations.get());
        equal(3, fixture.operations.get());
    }

    private static void recoveryCanReplaceExpiredSessionWithStatelessSession() {
        var fixture = new Fixture();
        fixture.statelessRecovery = true;
        var session = fixture.connection.openHttpSession(fixture::send, "fixture", "1");
        equal(200, session.send(session.session().operation("tools/call", "{}", 9)).status());
        equal(null, session.session().sessionId());
        equal(1, fixture.refreshes.get());
        equal(2, fixture.initializations.get());
        equal(3, fixture.operations.get());
        equal(200, session.send(session.session().operation("tools/call", "{}", 10)).status());
        equal(4, fixture.operations.get());
    }

    private static void ambiguousResponsesNeverReplay() {
        for (var response : java.util.List.of(
                new McpFlow.HttpResponse(404, Map.of(), "", false),
                new McpFlow.HttpResponse(500, Map.of(), "", true),
                new McpFlow.HttpResponse(200, Map.of(), "", false))) {
            var fixture = new Fixture();
            var session = fixture.connection.openHttpSession(fixture::send, "fixture", "1");
            fixture.expiredResponse = response;
            equal(response, session.send(session.session().operation("tools/call", "{}", 9)));
            equal(1, fixture.initializations.get());
            equal(2, fixture.operations.get());
        }
        var fixture = new Fixture();
        var session = fixture.connection.openHttpSession(fixture::send, "fixture", "1");
        fixture.expiredResponse = null;
        if (session.send(session.session().operation("tools/call", "{}", 9)) != null) throw new AssertionError();
        equal(1, fixture.initializations.get());
        equal(2, fixture.operations.get());
    }

    private static void repeatedExpiryIsBounded() {
        var fixture = new Fixture();
        var session = fixture.connection.openHttpSession(fixture::send, "fixture", "1");
        fixture.alwaysExpired = true;
        equal(404, session.send(session.session().operation("tools/call", "{}", 9)).status());
        equal(2, fixture.initializations.get());
        equal(3, fixture.operations.get());
    }

    private static void sessionRecoveryCannotDowngradeProtocol() {
        var fixture = new Fixture();
        var session = fixture.connection.openHttpSession(fixture::send, "fixture", "1");
        fixture.recoveryVersion = "2025-03-26";
        try {
            session.send(session.session().operation("tools/call", "{}", 9));
            throw new AssertionError("Recovery must retain negotiated protocol");
        } catch (IllegalArgumentException expected) { }
        equal(1, fixture.modernProbes.get());
        equal(2, fixture.operations.get());
        equal("2025-11-25", session.session().version());
    }

    private static final class Fixture {
        private final AtomicInteger refreshes = new AtomicInteger();
        private final AtomicInteger modernProbes = new AtomicInteger();
        private final AtomicInteger initializations = new AtomicInteger();
        private final AtomicInteger operations = new AtomicInteger();
        private McpFlow.HttpResponse expiredResponse = new McpFlow.HttpResponse(404, Map.of(), "", true);
        private boolean requireRefresh = true;
        private boolean alwaysExpired;
        private boolean statelessRecovery;
        private boolean statelessInitial;
        private String recoveryVersion = "2025-11-25";
        private final McpConnection connection = new McpConnection(new McpFlow(8192, 10), new CredentialProvider() {
            public Map<String, String> headers() { return Map.of("Authorization", "Bearer token-" + refreshes.get()); }
            public OperationRecovery beginOperation(String operation) {
                return response -> { refreshes.incrementAndGet(); return RecoveryResult.RETRY; };
            }
        });

        private McpFlow.HttpResponse send(com.mcpscanner.core.protocol.McpRequests.Request request) {
            if (request.body().contains("server/discover")) {
                modernProbes.incrementAndGet();
                return new McpFlow.HttpResponse(404, Map.of(), "", true);
            }
            if (request.body().contains("\"initialize\"")) {
                int number = initializations.incrementAndGet();
                return new McpFlow.HttpResponse(200, (number > 1 && statelessRecovery || number == 1 && statelessInitial) ? Map.of() : Map.of("Mcp-Session-Id", "session-" + number),
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"" + (number == 1 ? "2025-11-25" : recoveryVersion) + "\"}}", true);
            }
            if (request.body().contains("notifications/initialized")) return new McpFlow.HttpResponse(202, Map.of(), "", true);
            operations.incrementAndGet();
            if (requireRefresh && request.headers().get("Authorization").equals("Bearer token-0")) return new McpFlow.HttpResponse(401, Map.of(), "", true);
            if (alwaysExpired || "session-1".equals(request.headers().entrySet().stream().filter(entry -> entry.getKey().equalsIgnoreCase("MCP-Session-Id")).map(Map.Entry::getValue).findFirst().orElse(null))) return expiredResponse;
            equal(statelessRecovery ? null : "session-2", request.headers().entrySet().stream().filter(entry -> entry.getKey().equalsIgnoreCase("MCP-Session-Id")).map(Map.Entry::getValue).findFirst().orElse(null));
            return new McpFlow.HttpResponse(200, Map.of(), "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}", true);
        }
    }

    private static final class HandshakeChallengeFixture {
        private final int status;
        private int refreshes;
        private int initializations;
        private int operations;
        private int authorizations;
        private int approvals;
        private int credentialReads;
        private boolean alwaysChallenge;
        private boolean challengeOperation;
        private boolean anonymous;
        private com.mcpscanner.core.oauth.AuthorizationApproval approval =
            com.mcpscanner.core.oauth.AuthorizationApproval.REQUIRE_PROMPT;
        private final McpConnection connection;

        private HandshakeChallengeFixture(int status) {
            this.status = status;
            var binding = new com.mcpscanner.core.oauth.CredentialBinding(
                java.net.URI.create("https://issuer.example"), java.net.URI.create("https://resource.example/mcp"),
                "client", java.util.Set.of("read"), com.mcpscanner.core.oauth.OAuthGrantMode.AUTHORIZATION_CODE);
            var access = new OAuthCredentialAccess() {
                public java.util.Optional<com.mcpscanner.core.oauth.OAuthCredential> current() {
                    credentialReads++;
                    return java.util.Optional.of(new com.mcpscanner.core.oauth.OAuthCredential(
                        binding, "private-token-" + (refreshes + authorizations), "private-refresh", java.time.Instant.MAX, java.util.Set.of("read")));
                }
                public boolean refreshAvailable() { return true; }
                public void refresh() { refreshes++; }
                public void authorize(java.util.Set<String> scopes) {
                    equal(status == 403 ? java.util.Set.of("read", "write") : java.util.Set.of("read"), scopes);
                    authorizations++;
                }
            };
            connection = new McpConnection(new McpFlow(8192, 10), new OAuthCredentialProvider(binding, access,
                scopes -> {
                    equal(status == 403 ? java.util.Set.of("read", "write") : java.util.Set.of("read"), scopes);
                    approvals++;
                    return approval;
                }));
        }

        private HttpSession open() { return connection.openHttpSession(this::send, "fixture", "1"); }

        private McpFlow.HttpResponse send(com.mcpscanner.core.protocol.McpRequests.Request request) {
            if (anonymous && request.headers().keySet().stream().anyMatch(name -> name.equalsIgnoreCase("Authorization")))
                throw new AssertionError("Anonymous request carried credentials");
            if (request.body().contains("server/discover")) return new McpFlow.HttpResponse(404, Map.of(), "", true);
            if (request.body().contains("\"initialize\"")) {
                initializations++;
                if (initializations > 1 && (alwaysChallenge || refreshes + authorizations == 0))
                    return new McpFlow.HttpResponse(status, Map.of("WWW-Authenticate", status == 401
                        ? "Bearer error=\"invalid_token\"" : "Bearer error=\"insufficient_scope\", scope=\"write\""), "private-token-0", true);
                return new McpFlow.HttpResponse(200, Map.of("Mcp-Session-Id", initializations == 1 ? "session-old" : "session-recovered"),
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-11-25\"}}", true);
            }
            if (request.body().contains("notifications/initialized")) return new McpFlow.HttpResponse(202, Map.of(), "", true);
            operations++;
            if (challengeOperation && operations == 1) return new McpFlow.HttpResponse(401, Map.of(), "", true);
            if (operations == (challengeOperation ? 2 : 1)) return new McpFlow.HttpResponse(404, Map.of(), "", true);
            equal("Bearer private-token-1", request.headers().get("Authorization"));
            equal("session-recovered", request.headers().get("MCP-Session-Id"));
            return new McpFlow.HttpResponse(200, Map.of(), "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}", true);
        }
    }

    private static final int CONCURRENT_SENDS = 4;

    private static void concurrentSendsShareTheSessionWithoutWaitingForEachOther() {
        var allInFlight = new java.util.concurrent.CyclicBarrier(CONCURRENT_SENDS);
        var session = initializedSession(new AtomicInteger(), request -> {
            awaitTogether(allInFlight);
            return new McpFlow.HttpResponse(200, Map.of(), "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}", true);
        });
        equal(java.util.Collections.nCopies(CONCURRENT_SENDS, 200), sendConcurrently(session));
    }

    private static void concurrentExpiryReinitializesOnce() {
        var initializations = new AtomicInteger();
        var allSawExpiredSession = new java.util.concurrent.CyclicBarrier(CONCURRENT_SENDS);
        var session = initializedSession(initializations, request -> {
            if (!"s1".equals(request.headers().get("MCP-Session-Id")))
                return new McpFlow.HttpResponse(200, Map.of(), "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}", true);
            awaitTogether(allSawExpiredSession);
            return new McpFlow.HttpResponse(404, Map.of(), "Session not found", true);
        });
        equal(java.util.Collections.nCopies(CONCURRENT_SENDS, 200), sendConcurrently(session));
        equal(2, initializations.get());
        equal("s2", session.session().sessionId());
    }

    private static HttpSession initializedSession(AtomicInteger initializations, McpFlow.HttpPort operations) {
        var connection = new McpConnection(new McpFlow(8192, 10), CredentialProviders.none());
        return connection.openInitializeHttpSession(request -> {
            if (request.body().contains("\"initialize\"")) {
                int generation = initializations.incrementAndGet();
                return new McpFlow.HttpResponse(200, Map.of("MCP-Session-Id", "s" + generation),
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\"}}", true);
            }
            if (request.body().contains("notifications/initialized")) return new McpFlow.HttpResponse(202, Map.of(), "", true);
            return operations.send(request);
        }, "concurrency-fixture", "1", "2025-06-18");
    }

    private static java.util.List<Integer> sendConcurrently(HttpSession session) {
        var request = session.session().operation("tools/list", "{}", 9);
        var pool = java.util.concurrent.Executors.newFixedThreadPool(CONCURRENT_SENDS);
        try {
            var sends = new java.util.ArrayList<java.util.concurrent.Future<McpFlow.HttpResponse>>();
            for (int i = 0; i < CONCURRENT_SENDS; i++) sends.add(pool.submit(() -> session.send(request)));
            var statuses = new java.util.ArrayList<Integer>();
            for (var send : sends) statuses.add(send.get(10, java.util.concurrent.TimeUnit.SECONDS).status());
            return statuses;
        } catch (Exception failure) {
            throw new AssertionError("Concurrent sends did not all complete", failure);
        } finally {
            pool.shutdownNow();
        }
    }

    private static void awaitTogether(java.util.concurrent.CyclicBarrier barrier) {
        try {
            barrier.await(5, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Exception serialized) {
            throw new AssertionError("Sends were serialised instead of running together", serialized);
        }
    }

    private static void equal(Object expected, Object actual) {
        if (!java.util.Objects.equals(expected, actual)) throw new AssertionError("Expected " + expected + " but was " + actual);
    }
}
