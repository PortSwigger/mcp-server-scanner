package com.mcpscanner.proxy;

import com.mcpscanner.testutil.IdentityProbes;
import com.mcpscanner.testutil.ProxyRequestStubs;

import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.ScannerSentinels;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import fi.iki.elonen.NanoHTTPD;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class HttpIdentitySessionTest {
    @ParameterizedTest
    @ValueSource(strings = {"2025-03-26", "2025-06-18", "2025-11-25"})
    void eachManualIdentityCompletesItsOwnVersionedHandshake(String version) throws Exception {
        try (SessionServer server = new SessionServer(version)) {
            HttpClient http = HttpClient.newHttpClient();
            Logging logging = mock(Logging.class);
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                for (Map<String, String> identity : List.of(Map.of("Authorization", "Bearer B"),
                        Map.<String, String>of(), ScannerSentinels.stripAuthOnly(),
                        ScannerSentinels.withStripAuth("Authorization", "Bearer B"))) {
                    var headers = new HashMap<>(identity);
                    headers.put("Mcp-Session-Id", "session-A-1");
                    headers.put("MCP-Protocol-Version", "2099-01-01");
                    var response = proxy.serve(request(headers));
                    assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
                }
                var baseline = new HashMap<>(Map.of("Mcp-Session-Id", "session-A-1"));
                baseline.putAll(proxy.auditHeaders(baseline));
                assertThat(proxy.serve(request(baseline)).getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(server.operations).containsExactly("Bearer B", "anonymous", "anonymous", "Bearer B", "Bearer A");
                assertThat(server.initializations).containsExactly("Bearer A", "Bearer B", "anonymous", "anonymous", "Bearer B");
                assertThat(managed.scannerHeaders()).containsEntry("Mcp-Session-Id", "session-A-1");
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "2025-03-26,initialize,401", "2025-06-18,initialize,403", "2025-11-25,initialize,401",
            "2025-03-26,notifications/initialized,403", "2025-06-18,notifications/initialized,401",
            "2025-11-25,notifications/initialized,403", "2025-11-25,initialize,400", "2025-11-25,initialize,429",
            "2025-11-25,initialize,503", "2025-06-18,notifications/initialized,400",
            "2025-06-18,notifications/initialized,429"})
    void deniedIsolatedHandshakeDoesNotSendOperationOrReuseManagedSession(String version, String stage, int status)
            throws Exception {
        try (SessionServer server = new SessionServer(version)) {
            HttpClient http = HttpClient.newHttpClient();
            Logging logging = mock(Logging.class);
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            server.deniedMethod = stage;
            server.deniedStatus = status;
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                assertThat(proxy.serve(request(Map.of("Authorization", "Bearer B",
                        "Mcp-Session-Id", "session-A-1"))).getStatus().getRequestStatus()).isEqualTo(status);
                assertThat(server.operations).isEmpty();
                assertThat(server.identities).containsExactlyElementsOf(stage.equals("initialize")
                        ? List.of("Bearer A", "Bearer A", "Bearer B")
                        : List.of("Bearer A", "Bearer A", "Bearer B", "Bearer B"));
                assertThat(managed.scannerHeaders()).containsEntry("Mcp-Session-Id", "session-A-1");
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @org.junit.jupiter.api.Test
    void scannedInitializeRunsInASessionOfItsOwnSoTheLiveSessionKeepsWorking() throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            HttpClient http = HttpClient.newHttpClient();
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                var fuzzedInitialize = new HashMap<>(Map.of("Mcp-Session-Id", "session-A-1"));
                fuzzedInitialize.putAll(proxy.auditHeaders(fuzzedInitialize));
                var reply = proxy.serve(request(fuzzedInitialize, "{\"jsonrpc\":\"2.0\",\"id\":9,"
                        + "\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\","
                        + "\"capabilities\":{\"elicitation\":\"'\"},\"clientInfo\":{\"name\":\"x\",\"version\":\"1\"}}}"));

                var operation = new HashMap<>(Map.of("Mcp-Session-Id", "session-A-1"));
                operation.putAll(proxy.auditHeaders(operation));
                assertThat(reply.getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(proxy.serve(request(operation)).getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(server.initializations).containsExactly("Bearer A", "Bearer A");
                assertThat(server.deletedIdentities).containsExactly("Bearer A");
                assertThat(server.operationSessions).containsExactly("session-A-1");
                assertThat(managed.scannerHeaders()).containsEntry("Mcp-Session-Id", "session-A-1");
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void keepSessionSentinelSendsTheCredentialLessProbeOnTheLiveSession(boolean sessionIsCredential) throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            server.sessionIsCredential = sessionIsCredential;
            HttpClient http = HttpClient.newHttpClient();
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                var headers = keepSessionProbe("session-A-1");
                assertThat(proxy.serve(request(headers)).getStatus().getRequestStatus())
                        .isEqualTo(sessionIsCredential ? 200 : 403);
                assertThat(server.initializations).containsExactly("Bearer A");
                assertThat(server.identities).last().isEqualTo("anonymous");
                assertThat(server.operationSessions).isEqualTo(sessionIsCredential ? List.of("session-A-1") : List.of());
                assertThat(server.sentinels).isEmpty();
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @org.junit.jupiter.api.Test
    void keepSessionProbeMovesAnEarlierIssuedSessionIdToTheLiveOne() throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            server.sessionIsCredential = true;
            HttpClient http = HttpClient.newHttpClient();
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                server.expireNextOperation = true;
                var baseline = new HashMap<>(Map.of("Mcp-Session-Id", "session-A-1"));
                baseline.putAll(proxy.auditHeaders(baseline));
                assertThat(proxy.serve(request(baseline)).getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(managed.scannerHeaders()).containsEntry("Mcp-Session-Id", "session-A-2");

                assertThat(proxy.serve(request(keepSessionProbe("session-A-1"))).getStatus().getRequestStatus())
                        .isEqualTo(200);
                assertThat(server.operationSessions).last().isEqualTo("session-A-2");
                assertThat(server.identities).last().isEqualTo("anonymous");
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @org.junit.jupiter.api.Test
    void keepSessionWithoutStripAuthStaysOnTheAuthenticatedSession() throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            HttpClient http = HttpClient.newHttpClient();
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                var managedProbe = new HashMap<>(Map.of("Mcp-Session-Id", "session-A-1",
                        ScannerSentinels.KEEP_SESSION_HEADER, ScannerSentinels.SENTINEL_VALUE));
                managedProbe.putAll(proxy.auditHeaders(managedProbe));
                assertThat(proxy.serve(request(managedProbe)).getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(server.operations).containsExactly("Bearer A");
                assertThat(server.sentinels).isEmpty();
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }


    @ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({"false,Authorization,Bearer B", "true,Cookie,user=B"})
    void identityProbeUsesOnlyItsOwnCredentialsOnAnIsolatedSession(boolean managedAudit, String credential,
                                                                   String identity) throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            HttpClient http = HttpClient.newHttpClient();
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                var response = proxy.serve(request(IdentityProbes.headers(proxy, managedAudit, Map.of(credential, identity))));
                assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(new ObjectMapper().readTree(response.getData()).path("id").asInt()).isEqualTo(9);
                assertThat(server.operations).containsExactly(identity);
                assertThat(server.initializations).containsExactly("Bearer A", identity);
                assertThat(server.deletedIdentities).containsExactly(identity);
                assertThat(server.sentinels).isEmpty();
                assertThat(server.sessions).containsOnlyKeys("session-A-1");
                assertThat(managed.scannerHeaders()).containsEntry("Mcp-Session-Id", "session-A-1");
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void identityProbeOnModernHttpForwardsOnlyItsOwnCredentials(boolean managedAudit) throws Exception {
        try (SessionServer server = new SessionServer("2026-07-28")) {
            HttpClient http = HttpClient.newHttpClient();
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.MODERN_HTTP,
                    new BearerTokenAuthStrategy("A")));
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                var response = proxy.serve(request(IdentityProbes.headers(proxy, managedAudit, Map.of("Cookie", "user=B"))));
                assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(new ObjectMapper().readTree(response.getData()).path("id").asInt()).isEqualTo(9);
                assertThat(server.identities).last().isEqualTo("user=B");
                assertThat(server.sentinels).isEmpty();
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @org.junit.jupiter.api.Test
    void identityProbeKeepsItsOwnSessionIdWithoutReHandshakingThePrimary() throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            HttpClient http = HttpClient.newHttpClient();
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                var probe = IdentityProbes.headers(proxy, true, Map.of("Cookie", "user=B", "Mcp-Session-Id", "session-A-1"));
                assertThat(proxy.serve(request(probe)).getStatus().getRequestStatus()).isEqualTo(403);
                assertThat(server.identities).last().isEqualTo("user=B");
                assertThat(server.initializations).containsExactly("Bearer A");
                assertThat(server.deletedIdentities).isEmpty();
                assertThat(server.sessions).containsOnlyKeys("session-A-1");
                assertThat(server.sentinels).isEmpty();
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @org.junit.jupiter.api.Test
    void identityInitializeOpensASessionTheIdentityKeepsAcrossRequests() throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            HttpClient http = HttpClient.newHttpClient();
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                var initialize = IdentityProbes.headers(proxy, true, Map.of("Cookie", "user=B",
                        "MCP-Protocol-Version", "2025-11-25"));
                var admitted = proxy.serve(request(initialize, "{\"jsonrpc\":\"2.0\",\"id\":\"i\",\"method\":"
                        + "\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},"
                        + "\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}"));
                assertThat(admitted.getStatus().getRequestStatus()).isEqualTo(200);
                String session = admitted.getHeader("Mcp-Session-Id");
                assertThat(session).isNotNull().isNotEqualTo("session-A-1");
                assertThat(server.initializations).containsExactly("Bearer A", "user=B");
                assertThat(server.sessions).containsEntry(session, "user=B");
                assertThat(server.deletedIdentities).isEmpty();
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @org.junit.jupiter.api.Test
    void identityTakesPrecedenceOverStripAuthAndKeepSession() throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            server.sessionIsCredential = true;
            HttpClient http = HttpClient.newHttpClient();
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                server.expireNextOperation = true;
                var baseline = new HashMap<>(Map.of("Mcp-Session-Id", "session-A-1"));
                baseline.putAll(proxy.auditHeaders(baseline));
                assertThat(proxy.serve(request(baseline)).getStatus().getRequestStatus()).isEqualTo(200);
                int sessionOperations = server.operationSessions.size();

                var probe = keepSessionProbe("session-A-1");
                probe.put(ScannerSentinels.IDENTITY_HEADER, "anonymous-identity");
                assertThat(proxy.serve(request(probe)).getStatus().getRequestStatus()).isEqualTo(403);
                assertThat(server.operationSessions).hasSize(sessionOperations);
                assertThat(server.sentinels).isEmpty();
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @org.junit.jupiter.api.Test
    void identityCleanupNeverDeletesASessionIdThePrimaryWasIssued() throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            server.fixedSessionId = "session-shared";
            HttpClient http = HttpClient.newHttpClient();
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                assertThat(proxy.serve(request(IdentityProbes.headers(proxy, false, Map.of("Authorization", "Bearer B"))))
                        .getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(server.operations).containsExactly("Bearer B");
                assertThat(server.deletedIdentities).isEmpty();
                assertThat(server.sessions).containsOnlyKeys("session-shared");
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }


    private static Map<String, String> keepSessionProbe(String sessionId) {
        var headers = new HashMap<>(ScannerSentinels.stripAuthOnly());
        headers.put(ScannerSentinels.KEEP_SESSION_HEADER, ScannerSentinels.SENTINEL_VALUE);
        headers.put("Mcp-Session-Id", sessionId);
        return headers;
    }

    @org.junit.jupiter.api.Test
    void filtersTransportHeadersBeforeIsolatedHandshake() throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            HttpClient http = HttpClient.newHttpClient();
            Logging logging = mock(Logging.class);
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                assertThat(proxy.serve(request(Map.of("Authorization", "Bearer B", "Host", "injected.example",
                        "Content-Length", "58", "Connection", "keep-alive", "Keep-Alive", "timeout=5",
                        "Content-Type", "application/json", "Accept", "application/json")))
                        .getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(server.operations).containsExactly("Bearer B");
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @org.junit.jupiter.api.Test
    void isolatedSessionsAreDeletedBeforeTheNextRequestReachesTheServerCap() throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            HttpClient http = HttpClient.newHttpClient();
            Logging logging = mock(Logging.class);
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            server.maximumSessions = 2;
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                for (int request = 0; request < 4; request++) {
                    assertThat(proxy.serve(request(Map.of("Authorization", "Bearer B")))
                            .getStatus().getRequestStatus()).isEqualTo(200);
                }
                assertThat(server.deletedIdentities).containsExactly("Bearer B", "Bearer B", "Bearer B", "Bearer B");
                assertThat(server.sessions).containsOnlyKeys("session-A-1");
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @org.junit.jupiter.api.Test
    void refusedIsolatedInitializeRelaysTheServersStatusAndBodyRatherThanAProxyError() throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            HttpClient http = HttpClient.newHttpClient();
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            server.deniedMethod = "initialize";
            server.deniedStatus = 400;
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                var response = proxy.serve(request(Map.of("Authorization", "Bearer B")));
                assertThat(response.getStatus().getRequestStatus()).isEqualTo(400);
                assertThat(new String(response.getData().readAllBytes(), StandardCharsets.UTF_8)).isEqualTo("denied");
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @org.junit.jupiter.api.Test
    void failedInitializedNotificationStillDeletesTheAllocatedIsolatedSession() throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            HttpClient http = HttpClient.newHttpClient();
            Logging logging = mock(Logging.class);
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            server.deniedMethod = "notifications/initialized";
            server.deniedStatus = 403;
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                assertThat(proxy.serve(request(Map.of("Authorization", "Bearer B")))
                        .getStatus().getRequestStatus()).isEqualTo(403);
                assertThat(server.deletedIdentities).containsExactly("Bearer B");
                assertThat(server.sessions).containsOnlyKeys("session-A-1");
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"2025-03-26", "2025-06-18", "2025-11-25"})
    void staleIsolatedSessionReinitializesTheSameIdentityAndVersion(String version) throws Exception {
        try (SessionServer server = new SessionServer(version)) {
            HttpClient http = HttpClient.newHttpClient();
            Logging logging = mock(Logging.class);
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            server.expireNextOperation = true;
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                assertThat(proxy.serve(request(Map.of("Authorization", "Bearer B")))
                        .getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(server.initializations).containsExactly("Bearer A", "Bearer B", "Bearer B");
                assertThat(server.operationSessions).containsExactly("session-B-2", "session-B-3");
                assertThat(server.operations).containsExactly("Bearer B");
                assertThat(server.sessions).containsOnlyKeys("session-A-1");
                assertThat(managed.scannerHeaders()).containsEntry("Mcp-Session-Id", "session-A-1");
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @org.junit.jupiter.api.Test
    void sseInitializeAndOperationIgnoreServerRequestsAndUnrelatedReplies() throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            HttpClient http = HttpClient.newHttpClient();
            Logging logging = mock(Logging.class);
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            server.sseReplies = true;
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                var response = proxy.serve(request(Map.of("Authorization", "Bearer B")));
                assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
                JsonNode body = new ObjectMapper().readTree(response.getData());
                assertThat(body.path("result").has("tools")).isTrue();
                assertThat(body.has("method")).isFalse();
                assertThat(server.operations).containsExactly("Bearer B");
                assertThat(server.pingReplyIdentities).contains("Bearer B").containsOnly("Bearer B");
                assertThat(server.sessions).containsOnlyKeys("session-A-1");
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @org.junit.jupiter.api.Test
    void stalledSseInitializeTimesOutAndDeletesItsAllocatedSession() throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            HttpClient http = HttpClient.newHttpClient();
            Logging logging = mock(Logging.class);
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            server.stallReplies = true;
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).responseTimeout(java.time.Duration.ofMillis(200)).build();
            try {
                var response = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                    try {
                        return proxy.serve(request(Map.of("Authorization", "Bearer B")));
                    } catch (Exception failure) {
                        throw new java.util.concurrent.CompletionException(failure);
                    }
                }).get(3, java.util.concurrent.TimeUnit.SECONDS);
                assertThat(response.getStatus().getRequestStatus()).isEqualTo(502);
                assertThat(server.deletedIdentities).containsExactly("Bearer B");
                assertThat(server.sessions).containsOnlyKeys("session-A-1");
            } finally {
                server.releaseResponse.complete(null);
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"events", "bytes"})
    void sseNoiseBeyondResponseLimitsFailsAndDeletesItsAllocatedSession(String limit) throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            HttpClient http = HttpClient.newHttpClient();
            Logging logging = mock(Logging.class);
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            server.sseNoise = limit.equals("events")
                    ? "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"ping\"}\n\n".repeat(4097)
                    : (":" + "é".repeat(400_000) + "\n").repeat(12);
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                assertThat(proxy.serve(request(Map.of("Authorization", "Bearer B")))
                        .getStatus().getRequestStatus()).isEqualTo(502);
                assertThat(server.deletedIdentities).containsExactly("Bearer B");
                assertThat(server.sessions).containsOnlyKeys("session-A-1");
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @org.junit.jupiter.api.Test
    void malformedFuzzedOperationPreservesTheServersSseParseError() throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            HttpClient http = HttpClient.newHttpClient();
            Logging logging = mock(Logging.class);
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            server.sseReplies = true;
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                var response = proxy.serve(request(Map.of("Authorization", "Bearer B"), "invalid-json"));
                assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
                JsonNode body = new ObjectMapper().readTree(response.getData());
                assertThat(body.path("error").path("code").asInt()).isEqualTo(-32700);
                assertThat(body.path("id").isNull()).isTrue();
                assertThat(server.sessions).containsOnlyKeys("session-A-1");
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "[]", "true"})
    void invalidFuzzedIdsPreserveTheServersInvalidRequestError(String id) throws Exception {
        try (SessionServer server = new SessionServer("2025-11-25")) {
            HttpClient http = HttpClient.newHttpClient();
            Logging logging = mock(Logging.class);
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.STREAMABLE_HTTP,
                    new BearerTokenAuthStrategy("A")));
            server.sseReplies = true;
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                var response = proxy.serve(request(Map.of("Authorization", "Bearer B"),
                        "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"method\":\"tools/list\"}"));
                assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
                JsonNode body = new ObjectMapper().readTree(response.getData());
                assertThat(body).isNotNull();
                assertThat(body.path("error").path("code").asInt()).isEqualTo(-32600);
                assertThat(body.path("id").isNull()).isTrue();
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"reply", "events", "bytes"})
    void manualModernHttpCorrelatesSseRepliesWithinResponseLimits(String mode) throws Exception {
        try (SessionServer server = new SessionServer("2026-07-28")) {
            HttpClient http = HttpClient.newHttpClient();
            Logging logging = mock(Logging.class);
            McpScannerSession managed = new McpScannerSession(http, new McpEventLog(null));
            managed.connect(new McpServerConfig(server.endpoint(), TransportType.MODERN_HTTP,
                    new BearerTokenAuthStrategy("A")));
            server.sseReplies = true;
            if (mode.equals("events")) server.sseNoise = "event: message\ndata: {\"id\":77,\"method\":\"ping\"}\n\n".repeat(4097);
            if (mode.equals("bytes")) server.sseNoise = ":" + "x".repeat(1024 * 1024 + 1) + "\n\n";
            SseProxyServer proxy = TestSseProxies.builder(managed).httpClient(http).build();
            try {
                var response = proxy.serve(request(Map.of("Authorization", "Bearer B")));
                assertThat(response.getStatus().getRequestStatus()).isEqualTo(mode.equals("reply") ? 200 : 502);
                if (mode.equals("reply")) {
                    JsonNode body = new ObjectMapper().readTree(response.getData());
                    assertThat(body.path("result").has("tools")).isTrue();
                    assertThat(body.has("method")).isFalse();
                }
            } finally {
                proxy.stop();
                managed.disconnect();
            }
        }
    }

    private static NanoHTTPD.IHTTPSession request(Map<String, String> headers) throws Exception {
        return request(headers, "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/list\",\"params\":{}}");
    }

    private static NanoHTTPD.IHTTPSession request(Map<String, String> headers, String requestBody) throws Exception {
        var request = mock(NanoHTTPD.IHTTPSession.class);
        when(request.getMethod()).thenReturn(NanoHTTPD.Method.POST);
        when(request.getUri()).thenReturn("/mcp");
        ProxyRequestStubs.stubBody(request, headers, requestBody);
        return request;
    }

    private static final class SessionServer implements AutoCloseable {
        private final HttpServer server;
        private final String version;
        private final ObjectMapper json = new ObjectMapper();
        private final Map<String, String> sessions = new java.util.concurrent.ConcurrentHashMap<>();
        private final List<String> initialized = new java.util.concurrent.CopyOnWriteArrayList<>();
        private final List<String> initializations = new java.util.concurrent.CopyOnWriteArrayList<>();
        private final List<String> operations = new java.util.concurrent.CopyOnWriteArrayList<>();
        private final List<String> pingReplyIdentities = new java.util.concurrent.CopyOnWriteArrayList<>();
        private final List<String> identities = new java.util.concurrent.CopyOnWriteArrayList<>();
        private final List<String> deletedIdentities = new java.util.concurrent.CopyOnWriteArrayList<>();
        private final List<String> operationSessions = new java.util.concurrent.CopyOnWriteArrayList<>();
        private final List<String> sentinels = new java.util.concurrent.CopyOnWriteArrayList<>();
        private boolean sessionIsCredential;
        private boolean expireNextOperation;
        private String sseNoise;
        private boolean sseReplies;
        private boolean stallReplies;
        private final java.util.concurrent.CompletableFuture<Void> releaseResponse = new java.util.concurrent.CompletableFuture<>();
        private final java.util.concurrent.ExecutorService executor = java.util.concurrent.Executors.newCachedThreadPool();
        private int maximumSessions = Integer.MAX_VALUE;
        private String fixedSessionId;
        private String deniedMethod;
        private int deniedStatus;

        private SessionServer(String version) throws IOException {
            this.version = version;
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setExecutor(executor);
            server.createContext("/mcp", this::serve);
            server.start();
        }

        private String endpoint() { return "http://127.0.0.1:" + server.getAddress().getPort() + "/mcp"; }

        private void serve(HttpExchange exchange) throws IOException {
            try (exchange) {
                if (exchange.getRequestMethod().equals("DELETE")) {
                    String session = exchange.getRequestHeaders().getFirst("Mcp-Session-Id");
                    String identity = identityOf(exchange);
                    if (!identity.equals(sessions.get(session)) || !version.equals(exchange.getRequestHeaders()
                            .getFirst("MCP-Protocol-Version"))) {
                        reply(exchange, 403, "wrong cleanup identity or version"); return;
                    }
                    deletedIdentities.add(identity);
                    sessions.remove(session);
                    reply(exchange, 204, ""); return;
                }
                JsonNode request;
                try {
                    request = json.readTree(exchange.getRequestBody());
                } catch (IOException invalidJson) {
                    reply(exchange, 200, "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}");
                    return;
                }
                JsonNode id = request.get("id");
                if (id != null && !(id.isNull() || id.isTextual() || id.isNumber())) {
                    reply(exchange, 200, "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Invalid Request\"}}");
                    return;
                }
                exchange.getRequestHeaders().keySet().stream()
                        .filter(name -> name.toLowerCase(java.util.Locale.ROOT).startsWith("x-mcp-scanner"))
                        .forEach(sentinels::add);
                String method = request.path("method").asText();
                String identity = identityOf(exchange);
                if (!request.has("method") && request.has("result")) {
                    pingReplyIdentities.add(identity);
                    reply(exchange, 202, ""); return;
                }
                identities.add(identity);
                if (identity.equals("Bearer B") && method.equals(deniedMethod)) {
                    reply(exchange, deniedStatus, "denied"); return;
                }
                if (version.equals("2026-07-28")) {
                    if (method.equals("server/discover")) {
                        reply(exchange, 200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"capabilities\":{},\"supportedVersions\":[\"2026-07-28\"]}}");
                    } else {
                        reply(exchange, 200, "{\"jsonrpc\":\"2.0\",\"id\":" + request.get("id") + ",\"result\":{\"tools\":[]}}");
                    }
                    return;
                }
                String session = exchange.getRequestHeaders().getFirst("Mcp-Session-Id");
                String selected = exchange.getRequestHeaders().getFirst("MCP-Protocol-Version");
                if (method.equals("initialize")) {
                    if (session != null) { reply(exchange, 409, "session leaked into initialize"); return; }
                    if (sessions.size() >= maximumSessions) { reply(exchange, 429, "session cap"); return; }
                    initializations.add(identity);
                    session = fixedSessionId != null ? fixedSessionId
                            : "session-" + identity.replace("Bearer ", "") + "-" + initializations.size();
                    sessions.put(session, identity);
                    exchange.getResponseHeaders().add("Mcp-Session-Id", session);
                    reply(exchange, 200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"" + version
                            + "\",\"capabilities\":{},\"serverInfo\":{\"name\":\"fixture\",\"version\":\"1\"}}}");
                    return;
                }
                if (!admits(identity, session) || !version.equals(selected)) {
                    reply(exchange, 403, "wrong identity, session or version"); return;
                }
                if (method.equals("notifications/initialized")) {
                    initialized.add(session);
                    reply(exchange, 202, ""); return;
                }
                if (!initialized.contains(session)) { reply(exchange, 409, "initialization required"); return; }
                operationSessions.add(session);
                if (expireNextOperation) {
                    expireNextOperation = false;
                    sessions.remove(session);
                    reply(exchange, 404, "expired session"); return;
                }
                operations.add(identity);
                reply(exchange, 200, "{\"jsonrpc\":\"2.0\",\"id\":" + request.path("id") + ",\"result\":{\"tools\":[]}}");
            }
        }

        private static String identityOf(HttpExchange exchange) {
            String authorization = exchange.getRequestHeaders().getFirst("Authorization");
            if (authorization != null) return authorization;
            String cookie = exchange.getRequestHeaders().getFirst("Cookie");
            return cookie != null ? cookie : "anonymous";
        }

        private boolean admits(String identity, String session) {
            String owner = sessions.get(session);
            return identity.equals(owner) || (sessionIsCredential && owner != null && identity.equals("anonymous"));
        }

        private void reply(HttpExchange exchange, int status, String body) throws IOException {
            if (stallReplies && status == 200) {
                exchange.getResponseHeaders().add("Content-Type", "text/event-stream");
                exchange.sendResponseHeaders(status, 0);
                exchange.getResponseBody().write("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"ping\"}\n\n"
                        .getBytes(StandardCharsets.UTF_8));
                exchange.getResponseBody().flush();
                releaseResponse.join();
                return;
            }
            boolean stream = (sseReplies || sseNoise != null) && status == 200;
            if (stream) {
                body = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"ping\"}\n\n"
                        + "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":88,\"result\":{}}\n\n"
                        + "event: message\ndata: " + body + "\n\n";
            }
            if (sseNoise != null && status == 200) body = sseNoise + body;
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", stream ? "text/event-stream" : "application/json");
            exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
            exchange.getResponseBody().write(bytes);
        }

        @Override public void close() { releaseResponse.complete(null); server.stop(0); executor.shutdownNow(); }
    }
}
