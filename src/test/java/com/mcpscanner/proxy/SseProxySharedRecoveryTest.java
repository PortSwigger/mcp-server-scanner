package com.mcpscanner.proxy;

import com.mcpscanner.testutil.IdentityProbes;
import com.mcpscanner.testutil.ProxyRequestStubs;

import burp.api.montoya.logging.Logging;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.ScannerSentinels;
import fi.iki.elonen.NanoHTTPD;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import com.mcpscanner.core.connection.OperationRecovery;
import com.mcpscanner.core.connection.RecoveryResult;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.EnumSource;

import javax.net.ssl.SSLSession;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class SseProxySharedRecoveryTest {
    private static final String CHALLENGE = "Bearer error=\"insufficient_scope\", scope=\"write\"";

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void strippedProbeUsesOnlyReplacementIdentityAcrossProtectedSseSession(boolean replacement) throws Exception {
        try (Server server = new Server(Stage.OPEN, 401, 0)) {
            server.requiredSessionAuthorization = "Bearer forged";
            McpScannerSession scanner = scanner();
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var headers = replacement ? ScannerSentinels.withStripAuth("Authorization", "Bearer forged")
                        : ScannerSentinels.stripAuthOnly();
                var result = proxy.serve(request(headers));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(replacement ? 200 : 401);
                assertThat(server.requests).hasSize(replacement ? 4 : 1);
                assertThat(server.requests).allSatisfy(sent -> {
                    assertThat(sent.headers().firstValue("Authorization"))
                            .isEqualTo(replacement ? Optional.of("Bearer forged") : Optional.empty());
                    assertThat(sent.headers().firstValue(ScannerSentinels.STRIP_AUTH_HEADER)).isEmpty();
                });
                verify(scanner, never()).scannerHeaders();
                verify(scanner, never()).beginAuthOperation();
            } finally { proxy.stop(); }
        }
    }

    @Test
    void scannedInitializeIsPostedOnAStreamOfItsOwnNotTheLiveOne() throws Exception {
        try (Server server = new Server(Stage.OPERATION, 401, 0)) {
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer A"));
            when(scanner.beginAuthOperation()).thenReturn(mock(OperationRecovery.class));
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                assertThat(proxy.serve(request(proxy.auditHeaders(Map.of()))).getStatus().getRequestStatus())
                        .isEqualTo(200);
                int liveStreamRequests = server.requests.size();

                var reply = proxy.serve(request(proxy.auditHeaders(Map.of()), "{\"jsonrpc\":\"2.0\",\"id\":7,"
                        + "\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\","
                        + "\"capabilities\":{\"sampling\":\"'\"},\"clientInfo\":{\"name\":\"x\",\"version\":\"1\"}}}"));

                assertThat(reply.getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(server.opens).isEqualTo(2);
                List<HttpRequest> scanned = server.requests.subList(liveStreamRequests, server.requests.size());
                assertThat(scanned.get(0).method()).isEqualTo("GET");
                assertThat(scanned).allSatisfy(sent -> assertThat(sent.headers().firstValue("Authorization"))
                        .contains("Bearer A"));
            } finally { proxy.stop(); }
        }
    }

    @ParameterizedTest
    @CsvSource({"OPEN,401", "OPEN,403", "INITIALIZE,401", "INITIALIZE,403",
            "INITIALIZED,401", "INITIALIZED,403", "OPERATION,401", "OPERATION,403"})
    void anonymousDenialPreservesChallengeMetadataWithoutCredentials(Stage stage, int status) throws Exception {
        try (Server server = new Server(stage, status)) {
            McpScannerSession scanner = scanner();
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var result = proxy.serve(request(ScannerSentinels.stripAuthOnly()));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(status);
                assertThat(result.getHeader("WWW-Authenticate")).isEqualTo(CHALLENGE);
                assertThat(server.requests).allSatisfy(sent ->
                        assertThat(sent.headers().firstValue("Authorization")).isEmpty());
                assertThat(server.opens).isEqualTo(1);
                verify(scanner, never()).scannerHeaders();
                verify(scanner, never()).beginAuthOperation();
            } finally { proxy.stop(); }
        }
    }

    @ParameterizedTest
    @CsvSource({"OPEN,401", "OPEN,403", "INITIALIZE,401", "INITIALIZE,403",
            "INITIALIZED,401", "INITIALIZED,403", "OPERATION,401", "OPERATION,403"})
    void authenticatedChallengeUsesOneSharedRecoveryContext(Stage stage, int status) throws Exception {
        try (Server server = new Server(stage, status, 1)) {
            McpScannerSession scanner = scanner();
            var token = new java.util.concurrent.atomic.AtomicReference<>("old");
            when(scanner.scannerHeaders()).thenAnswer(ignored -> Map.of("Authorization", "Bearer " + token.get()));
            OperationRecovery recovery = mock(OperationRecovery.class);
            when(scanner.beginAuthOperation()).thenReturn(recovery);
            when(recovery.recover(any())).thenAnswer(call -> {
                var response = (com.mcpscanner.core.protocol.McpFlow.HttpResponse) call.getArgument(0);
                assertThat(response.status()).isEqualTo(status);
                assertThat(response.headers()).containsEntry("WWW-Authenticate", CHALLENGE);
                token.set("new");
                return RecoveryResult.RETRY;
            });
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var headers = new java.util.HashMap<>(Map.of("Authorization", "Bearer old", "X-Correlation", "trace"));
                headers.putAll(proxy.auditHeaders(headers));
                headers.remove("Authorization");
                var result = proxy.serve(request(headers));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(server.opens).isEqualTo(2);
                verify(scanner).beginAuthOperation();
                verify(recovery).recover(any());
                List<HttpRequest> opens = server.requests.stream().filter(r -> r.method().equals("GET")).toList();
                assertThat(opens.get(0).headers().firstValue("Authorization")).contains("Bearer old");
                assertThat(opens.get(1).headers().firstValue("Authorization")).contains("Bearer new");
                HttpRequest operation = server.requests.get(server.requests.size() - 1);
                assertThat(operation.headers().firstValue("Authorization")).contains("Bearer new");
                assertThat(operation.headers().firstValue("X-Correlation")).contains("trace");
            } finally { proxy.stop(); }
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {401, 403})
    void explicitManualCredentialDenialNeverTriggersSharedRecovery(int status) throws Exception {
        try (Server server = new Server(Stage.OPERATION, status)) {
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer session"));
            OperationRecovery recovery = mock(OperationRecovery.class);
            when(scanner.beginAuthOperation()).thenReturn(recovery);
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var result = proxy.serve(request(Map.of("authorization", "Bearer explicit")));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(status);
                assertThat(server.opens).isEqualTo(1);
                assertThat(server.requests.get(server.requests.size() - 1).headers().firstValue("Authorization"))
                        .contains("Bearer explicit");
                verifyNoInteractions(recovery);
            } finally { proxy.stop(); }
        }
    }

    @Test
    void addedCustomCredentialMakesCopiedAuditAnIsolatedManualRequest() throws Exception {
        try (Server server = new Server(Stage.OPERATION, 401, 0)) {
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer A"));
            when(scanner.beginAuthOperation()).thenReturn(mock(OperationRecovery.class));
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var headers = new java.util.HashMap<>(Map.of("Authorization", "Bearer A"));
                headers.putAll(proxy.auditHeaders(headers));
                headers.put("X-Api-Key", "B");
                assertThat(proxy.serve(request(headers)).getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(server.requests).allSatisfy(sent -> {
                    assertThat(sent.headers().firstValue("Authorization")).contains("Bearer A");
                    assertThat(sent.headers().firstValue("X-Api-Key")).contains("B");
                });
                verify(scanner, never()).scannerHeaders();
                verify(scanner, never()).beginAuthOperation();
            } finally { proxy.stop(); }
        }
    }

    @ParameterizedTest
    @CsvSource({"Authorization,Bearer original,Bearer manual", "Cookie,session=original,session=manual", "X-Api-Key,original,manual"})
    void copiedAuditWithEditedCredentialsPreservesManualRequest(String name, String original, String edited) throws Exception {
        try (Server server = new Server(Stage.OPERATION, 401)) {
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of(name, original));
            OperationRecovery recovery = mock(OperationRecovery.class);
            when(scanner.beginAuthOperation()).thenReturn(recovery);
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var headers = new java.util.HashMap<>(proxy.auditHeaders(Map.of(name, original)));
                headers.put(name.toLowerCase(java.util.Locale.ROOT), edited);
                var result = proxy.serve(request(headers));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(401);
                assertThat(server.requests.get(server.requests.size() - 1).headers().firstValue(name)).contains(edited);
                verifyNoInteractions(recovery);
            } finally { proxy.stop(); }
        }
    }

    @ParameterizedTest
    @CsvSource({"Authorization,Bearer original,Bearer manual", "Cookie,session=original,session=manual", "X-Api-Key,original,manual"})
    void repeaterWithFullHttpHeadersPreservesManualCredentialsOnGetAndPost(String name, String original, String edited) throws Exception {
        try (Server server = new Server(Stage.OPERATION, 401, 0)) {
            McpScannerSession scanner = scanner();
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var headers = new java.util.HashMap<>(proxy.auditHeaders(Map.of(name, original)));
                headers.put(name, edited);
                headers.put("host", "127.0.0.1:12345");
                headers.put("content-length", "58");
                headers.put("content-type", "application/json");
                headers.put("connection", "keep-alive, X-Hop-Secret");
                headers.put("X-Hop-Secret", "private-hop");
                headers.put("proxy-authorization", "Basic proxy-secret");
                headers.put("proxy-connection", "keep-alive");
                var result = proxy.serve(request(headers));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(server.requests).anyMatch(sent -> sent.method().equals("GET"));
                assertThat(server.requests).anyMatch(sent -> sent.method().equals("POST"));
                assertThat(server.requests).allSatisfy(sent -> {
                    assertThat(sent.headers().firstValue(name)).contains(edited);
                    for (String forbidden : List.of("Host", "Content-Length", "Connection", "X-Hop-Secret",
                            "Proxy-Authorization", "Proxy-Connection", "Transfer-Encoding", ScannerSentinels.AUDIT_CAPABILITY_HEADER)) {
                        assertThat(sent.headers().firstValue(forbidden)).isEmpty();
                    }
                });
                verify(scanner, never()).scannerHeaders();
                verify(scanner, never()).beginAuthOperation();
            } finally { proxy.stop(); }
        }
    }

    @Test
    void nanoHttpdAddressMetadataDoesNotSelectAnIsolatedManualIdentity() throws Exception {
        try (Server server = new Server(Stage.OPERATION, 401, 0)) {
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer configured"));
            when(scanner.beginAuthOperation()).thenReturn(mock(OperationRecovery.class));
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var headers = new java.util.HashMap<>(proxy.auditHeaders(Map.of()));
                headers.put("remote-addr", "127.0.0.1");
                headers.put("http-client-ip", "127.0.0.1");
                var result = proxy.serve(request(headers));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(server.requests).allSatisfy(sent ->
                        assertThat(sent.headers().firstValue("Authorization")).contains("Bearer configured"));
                verify(scanner).scannerHeaders();
            } finally { proxy.stop(); }
        }
    }

    @Test
    void unmarkedRepeaterUsesOnlyExplicitIdentityThroughoutSseHandshake() throws Exception {
        try (Server server = new Server(Stage.OPERATION, 401, 0)) {
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer A"));
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var result = proxy.serve(request(Map.of("Authorization", "Bearer B", "Host", "localhost:1234",
                        "Content-Length", "58", "Content-Type", "application/json")));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(server.requests).allSatisfy(sent ->
                        assertThat(sent.headers().firstValue("Authorization")).contains("Bearer B"));
                verify(scanner, never()).scannerHeaders();
                verify(scanner, never()).beginAuthOperation();
            } finally { proxy.stop(); }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"Authorization", "Cookie", "X-Api-Key"})
    void copiedAuditWithRemovedCredentialDoesNotRestoreIt(String removed) throws Exception {
        try (Server server = new Server(Stage.OPERATION, 401)) {
            McpScannerSession scanner = scanner();
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var baseline = Map.of("Authorization", "Bearer original", "Cookie", "session=original", "X-Api-Key", "original");
                var headers = new java.util.HashMap<>(baseline);
                headers.putAll(proxy.auditHeaders(baseline));
                if (removed.equals("Authorization")) headers.remove(ScannerSentinels.AUDIT_CAPABILITY_HEADER);
                headers.remove(removed);
                assertThat(proxy.serve(request(headers)).getStatus().getRequestStatus()).isEqualTo(401);
                assertThat(server.requests).allSatisfy(sent -> {
                    assertThat(sent.headers().firstValue(removed)).isEmpty();
                    assertThat(sent.headers().firstValue(ScannerSentinels.AUDIT_CAPABILITY_HEADER)).isEmpty();
                });
                verify(scanner, never()).scannerHeaders();
                verify(scanner, never()).beginAuthOperation();
            } finally { proxy.stop(); }
        }
    }

    @Test
    void capturedConnectionCannotIssueProvenanceAfterIdenticalReconnect() {
        McpScannerSession scanner = scanner();
        SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(mock(HttpClient.class)).build();
        try {
            var captured = proxy.captureScanConnection();
            proxy.resetScanSession();
            org.assertj.core.api.Assertions.assertThatThrownBy(() -> captured.headers(Map.of("Authorization", "Bearer same")))
                    .isInstanceOf(IllegalStateException.class);
            verify(scanner, never()).scannerHeaders();
        } finally { proxy.stop(); }
    }


    @Test
    void pendingScopeRecoveryAllowsDisconnectAndRejectsRetryWithNewIdentity() throws Exception {
        try (Server server = new Server(Stage.OPERATION, 403)) {
            McpScannerSession scanner = scanner();
            var generation = new AtomicLong();
            when(scanner.connectionGeneration()).thenAnswer(call -> generation.get());
            when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer A"));
            OperationRecovery recovery = mock(OperationRecovery.class);
            when(scanner.beginAuthOperation()).thenReturn(recovery);
            var executor = java.util.concurrent.Executors.newSingleThreadExecutor();
            when(recovery.recover(any())).thenAnswer(call -> {
                executor.submit(() -> {
                    synchronized (scanner) {
                        generation.incrementAndGet();
                    }
                }).get(2, java.util.concurrent.TimeUnit.SECONDS);
                return RecoveryResult.RETRY;
            });
            var proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                assertThat(proxy.serve(request(proxy.auditHeaders(Map.of()))).getStatus().getRequestStatus()).isEqualTo(409);
                assertThat(server.opens).isEqualTo(1);
                verify(scanner).scannerHeaders();
                assertThat(server.requests).allSatisfy(sent ->
                        assertThat(sent.headers().firstValue("Authorization")).contains("Bearer A"));
            } finally {
                proxy.stop();
                executor.shutdownNow();
            }
        }
    }

    @Test
    void resettingConnectionDuringRecoveryCannotRetryWithNewIdentity() throws Exception {
        try (Server server = new Server(Stage.OPERATION, 401, 1)) {
            McpScannerSession scanner = scanner();
            var token = new java.util.concurrent.atomic.AtomicReference<>("A");
            when(scanner.scannerHeaders()).thenAnswer(ignored -> Map.of("Authorization", "Bearer " + token.get()));
            OperationRecovery recovery = mock(OperationRecovery.class);
            when(scanner.beginAuthOperation()).thenReturn(recovery);
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            when(recovery.recover(any())).thenAnswer(ignored -> {
                proxy.resetScanSession();
                token.set("B");
                return RecoveryResult.RETRY;
            });
            try {
                var headers = new java.util.HashMap<>(proxy.auditHeaders(Map.of("Authorization", "Bearer A")));
                assertThat(proxy.serve(request(headers)).getStatus().getRequestStatus()).isEqualTo(409);
                assertThat(server.requests).allSatisfy(sent ->
                        assertThat(sent.headers().firstValue("Authorization")).contains("Bearer A"));
            } finally { proxy.stop(); }
        }
    }

    @Test
    void underlyingReconnectRetiresOldMarkerBeforeProxyDisconnectListenerRuns() throws Exception {
        McpScannerSession scanner = scanner();
        SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(mock(HttpClient.class)).build();
        try {
            var headers = new java.util.HashMap<>(Map.of("Authorization", "Bearer A"));
            headers.putAll(proxy.auditHeaders(headers));
            when(scanner.connectionGeneration()).thenReturn(1L);
            when(scanner.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
            assertThat(proxy.serve(request(headers)).getStatus().getRequestStatus()).isEqualTo(409);
            verify(scanner, never()).sendHttpOperation(any());
            verify(scanner, never()).scannerHeaders();
        } finally { proxy.stop(); }
    }

    @Test
    void reconnectFromSseToHttpDuringDispatchCannotSendWithNewProvider() throws Exception {
        McpScannerSession scanner = scanner();
        SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(mock(HttpClient.class)).build();
        try {
            var headers = new java.util.HashMap<>(Map.of("Authorization", "Bearer A"));
            headers.putAll(proxy.auditHeaders(headers));
            when(scanner.transportType()).thenAnswer(call -> {
                proxy.resetScanSession();
                when(scanner.resolvedEndpoint()).thenReturn("https://server-b.example/mcp");
                return TransportType.STREAMABLE_HTTP;
            });
            assertThat(proxy.serve(request(headers)).getStatus().getRequestStatus()).isEqualTo(409);
            verify(scanner, never()).sendHttpOperation(any());
            verify(scanner, never()).scannerHeaders();
            verify(scanner, never()).beginAuthOperation();
        } finally { proxy.stop(); }
    }

    @Test
    void retiredAuditCannotAdoptReconnectedIdentity() throws Exception {
        try (Server server = new Server(Stage.OPERATION, 401, 0)) {
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer A"));
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var headers = new java.util.HashMap<>(proxy.auditHeaders(Map.of("Authorization", "Bearer A")));
                headers.put("Authorization", "Bearer A");
                proxy.resetScanSession();
                when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer B"));
                var result = proxy.serve(request(headers));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(409);
                assertThat(server.requests).isEmpty();
                verify(scanner, never()).beginAuthOperation();
            } finally { proxy.stop(); }
        }
    }

    @Test
    void retiredAnonymousProbeCannotBypassConnectionExpiry() throws Exception {
        try (Server server = new Server(Stage.OPERATION, 401, 0)) {
            McpScannerSession scanner = scanner();
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var headers = new java.util.HashMap<>(proxy.auditHeaders(Map.of("X-Api-Key", "A")));
                headers.putAll(ScannerSentinels.stripAuthOnly());
                proxy.resetScanSession();
                var result = proxy.serve(request(headers));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(409);
                assertThat(server.requests).isEmpty();
                verify(scanner, never()).scannerHeaders();
                verify(scanner, never()).beginAuthOperation();
            } finally { proxy.stop(); }
        }
    }

    @Test
    void auditTemplateUsesCurrentCredentialsAcrossConsecutiveRequestsAfterRefresh() throws Exception {
        try (Server server = new Server(Stage.OPERATION, 401, 1)) {
            server.requiredOperationAuthorization = "Bearer new";
            McpScannerSession scanner = scanner();
            var token = new java.util.concurrent.atomic.AtomicReference<>("old");
            when(scanner.scannerHeaders()).thenAnswer(ignored -> Map.of("Authorization", "Bearer " + token.get()));
            OperationRecovery recovery = mock(OperationRecovery.class);
            when(scanner.beginAuthOperation()).thenReturn(recovery);
            when(recovery.recover(any())).thenAnswer(ignored -> {
                token.set("new");
                return RecoveryResult.RETRY;
            });
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var template = new java.util.HashMap<>(proxy.auditHeaders(Map.of("Authorization", "Bearer old")));
                assertThat(proxy.serve(request(template)).getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(proxy.serve(request(template)).getStatus().getRequestStatus()).isEqualTo(200);
                verify(recovery).recover(any());
                assertThat(server.requests.get(server.requests.size() - 1).headers().firstValue("Authorization"))
                        .contains("Bearer new");
            } finally { proxy.stop(); }
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void invalidOrForeignAuditCapabilityPreservesExplicitCredentialsWithoutRecovery(boolean foreign) throws Exception {
        try (Server server = new Server(Stage.OPERATION, 401)) {
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer current"));
            OperationRecovery recovery = mock(OperationRecovery.class);
            when(scanner.beginAuthOperation()).thenReturn(recovery);
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            SseProxyServer other = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                String capability = foreign ? other.auditHeaders(Map.of("Authorization", "Bearer manual")).get(ScannerSentinels.AUDIT_CAPABILITY_HEADER) : "forged";
                var result = proxy.serve(request(Map.of(ScannerSentinels.AUDIT_CAPABILITY_HEADER, capability,
                        "Authorization", "Bearer manual")));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(401);
                assertThat(server.requests.get(server.requests.size() - 1).headers().firstValue("Authorization"))
                        .contains("Bearer manual");
                assertThat(server.requests).allSatisfy(sent ->
                        assertThat(sent.headers().firstValue(ScannerSentinels.AUDIT_CAPABILITY_HEADER)).isEmpty());
                verifyNoInteractions(recovery);
            } finally { proxy.stop(); other.stop(); }
        }
    }

    @Test
    void stripAuthTakesPrecedenceOverValidAuditCapabilityWithoutCredentialReads() throws Exception {
        try (Server server = new Server(Stage.OPERATION, 403)) {
            McpScannerSession scanner = scanner();
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var headers = new java.util.HashMap<>(proxy.auditHeaders(Map.of()));
                headers.putAll(ScannerSentinels.stripAuthOnly());
                assertThat(proxy.serve(request(headers)).getStatus().getRequestStatus()).isEqualTo(403);
                assertThat(server.opens).isEqualTo(1);
                assertThat(server.requests).allSatisfy(sent -> {
                    assertThat(sent.headers().firstValue("Authorization")).isEmpty();
                    assertThat(sent.headers().firstValue(ScannerSentinels.AUDIT_CAPABILITY_HEADER)).isEmpty();
                });
                verify(scanner, never()).scannerHeaders();
                verify(scanner, never()).beginAuthOperation();
            } finally { proxy.stop(); }
        }
    }

    @Test
    void auditCapabilityUsesCurrentCustomCredentialsAndIsNeverForwarded() throws Exception {
        try (Server server = new Server(Stage.OPERATION, 403, 0)) {
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of("X-Api-Key", "current", "Cookie", "session=current"));
            when(scanner.beginAuthOperation()).thenReturn(mock(OperationRecovery.class));
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var headers = Map.of(ScannerSentinels.AUDIT_CAPABILITY_HEADER.toLowerCase(java.util.Locale.ROOT),
                        proxy.auditHeaders(Map.of("X-Api-Key", "stale", "Cookie", "session=stale")).get(ScannerSentinels.AUDIT_CAPABILITY_HEADER),
                        "x-api-key", "stale", "cookie", "session=stale");
                assertThat(proxy.serve(request(headers)).getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(server.requests).allSatisfy(sent -> {
                    assertThat(sent.headers().firstValue("X-Api-Key")).contains("current");
                    assertThat(sent.headers().firstValue("Cookie")).contains("session=current");
                    assertThat(sent.headers().firstValue(ScannerSentinels.AUDIT_CAPABILITY_HEADER)).isEmpty();
                });
            } finally { proxy.stop(); }
        }
    }

    @ParameterizedTest
    @EnumSource(value = TransportType.class, names = {"STREAMABLE_HTTP", "MODERN_HTTP"})
    void httpAuditsReceiveAuthenticatedProvenance(TransportType transport) {
        McpScannerSession scanner = mock(McpScannerSession.class);
        when(scanner.transportType()).thenReturn(transport);
        when(scanner.eventLog()).thenReturn(McpEventLog.noop());
        SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(mock(HttpClient.class)).build();
        assertThat(proxy.auditHeaders(Map.of())).containsKey(ScannerSentinels.AUDIT_CAPABILITY_HEADER);
        proxy.stop();
    }

    @ParameterizedTest
    @ValueSource(ints = {401, 403})
    void repeatedChallengesHaveOneContextAndAbsoluteRetryBound(int status) throws Exception {
        try (Server server = new Server(Stage.OPEN, status)) {
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer session"));
            OperationRecovery recovery = mock(OperationRecovery.class);
            when(scanner.beginAuthOperation()).thenReturn(recovery);
            when(recovery.recover(any())).thenReturn(RecoveryResult.RETRY);
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var result = proxy.serve(request(proxy.auditHeaders(Map.of())));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(status);
                assertThat(server.opens).isEqualTo(3);
                verify(scanner).beginAuthOperation();
                verify(recovery, times(2)).recover(any());
            } finally { proxy.stop(); }
        }
    }

    @Test
    void recoveryBudgetSpansDifferentHandshakeStages() throws Exception {
        try (Server server = new Server(Stage.OPEN, 401)) {
            server.deniedStages = Map.of(1, Stage.OPEN, 2, Stage.INITIALIZED);
            server.deniedStatuses = Map.of(1, 401, 2, 403);
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer session"));
            OperationRecovery recovery = mock(OperationRecovery.class);
            when(scanner.beginAuthOperation()).thenReturn(recovery);
            when(recovery.recover(any())).thenReturn(RecoveryResult.RETRY, RecoveryResult.STOP);
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var result = proxy.serve(request(proxy.auditHeaders(Map.of())));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(403);
                assertThat(server.opens).isEqualTo(2);
                var challenges = org.mockito.ArgumentCaptor.forClass(com.mcpscanner.core.protocol.McpFlow.HttpResponse.class);
                verify(recovery, times(2)).recover(challenges.capture());
                assertThat(challenges.getAllValues()).extracting(com.mcpscanner.core.protocol.McpFlow.HttpResponse::status)
                        .containsExactly(401, 403);
                verify(scanner).beginAuthOperation();
            } finally { proxy.stop(); }
        }
    }

    @ParameterizedTest
    @EnumSource(value = RecoveryResult.class, names = {"APPROVAL_REQUIRED", "DENIED"})
    void refusedScopeApprovalFailsClosedWithoutRetry(RecoveryResult refusal) throws Exception {
        try (Server server = new Server(Stage.OPERATION, 403)) {
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer session"));
            OperationRecovery recovery = mock(OperationRecovery.class);
            when(scanner.beginAuthOperation()).thenReturn(recovery);
            when(recovery.recover(any())).thenReturn(refusal);
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var result = proxy.serve(request(proxy.auditHeaders(Map.of())));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(502);
                assertThat(server.opens).isEqualTo(1);
                verify(scanner).beginAuthOperation();
                verify(recovery).recover(any());
            } finally { proxy.stop(); }
        }
    }

    @Test
    void authRecoveryClosesPreviousStreamAndReleasesConcurrentWaiter() throws Exception {
        try (Server server = new Server(Stage.OPERATION, 401, 1)) {
            server.holdFirstOperation = true;
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer session"));
            when(scanner.beginAuthOperation()).thenReturn(response -> RecoveryResult.RETRY);
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var first = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                    try { return proxy.serve(request(proxy.auditHeaders(Map.of()))); }
                    catch (Exception e) { throw new RuntimeException(e); }
                });
                server.heldOperation.get(2, java.util.concurrent.TimeUnit.SECONDS);
                var second = proxy.serve(request(proxy.auditHeaders(Map.of())));
                assertThat(second.getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(first.get(2, java.util.concurrent.TimeUnit.SECONDS).getStatus().getRequestStatus()).isEqualTo(502);
                assertThat(server.opens).isEqualTo(2);
                assertThat(proxy.concurrencyPermitsAvailable()).isEqualTo(32);
            } finally { proxy.stop(); }
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void authOperationUsesSelectedProviderAndDoesNotReadTokenHeaders() throws Exception {
        var provider = mock(com.mcpscanner.core.connection.CredentialProvider.class);
        when(provider.headers()).thenReturn(Map.of("Authorization", "Bearer session"));
        when(provider.headerNames()).thenReturn(java.util.Set.of("Authorization"));
        when(provider.beginOperation(anyString())).thenAnswer(call -> (OperationRecovery) response -> RecoveryResult.STOP);
        var auth = mock(com.mcpscanner.auth.AuthStrategy.class);
        when(auth.headers()).thenReturn(Map.of("Authorization", "Bearer session"));
        when(auth.sharedCredentialProvider()).thenReturn(Optional.of(provider));
        HttpClient client = mock(HttpClient.class);
        String admission = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"capabilities\":{},\"supportedVersions\":[\"2026-07-28\"]}}";
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenReturn(
                new WireResponse<>(200, new ByteArrayInputStream(admission.getBytes(StandardCharsets.UTF_8)),
                        Map.of("Content-Type", List.of("application/json"))));
        var scanner = new McpScannerSession(client, new McpEventLog(null));
        scanner.connect(new com.mcpscanner.client.McpServerConfig("https://upstream/mcp", TransportType.MODERN_HTTP, auth));
        try {
            clearInvocations(provider);
            assertThat(scanner.beginAuthOperation()).isNotSameAs(scanner.beginAuthOperation());
            var operations = org.mockito.ArgumentCaptor.forClass(String.class);
            verify(provider, times(2)).beginOperation(operations.capture());
            assertThat(operations.getAllValues()).doesNotHaveDuplicates().allSatisfy(id -> assertThat(id).isNotBlank());
            verify(provider, never()).headers();
            verify(provider, never()).headerNames();
        } finally { scanner.disconnect(); }
    }

    @Test
    void stoppedProxyReturnsExpiredConnectionWithoutReopeningAfterAuthenticationRecovery() throws Exception {
        try (Server server = new Server(Stage.OPEN, 401, 1)) {
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer session"));
            var currentProxy = new java.util.concurrent.atomic.AtomicReference<SseProxyServer>();
            when(scanner.beginAuthOperation()).thenReturn(response -> {
                currentProxy.get().stop();
                return RecoveryResult.RETRY;
            });
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            currentProxy.set(proxy);
            try {
                var result = proxy.serve(request(proxy.auditHeaders(Map.of())));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(409);
                assertThat(server.opens).isEqualTo(1);
                verify(scanner).scannerHeaders();
            } finally { proxy.stop(); }
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void underlyingReconnectBeforeProxyResetCannotForwardOldRequestWithNewIdentity() throws Exception {
        HttpClient client = mock(HttpClient.class);
        var requests = new java.util.concurrent.CopyOnWriteArrayList<HttpRequest>();
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenAnswer(call -> {
            requests.add(call.getArgument(0));
            return modernAdmission();
        });
        var scanner = new McpScannerSession(client, McpEventLog.noop());
        scanner.connect(new com.mcpscanner.client.McpServerConfig("https://server-a.example/mcp",
                TransportType.MODERN_HTTP, () -> Map.of("Authorization", "Bearer A")));
        var proxy = TestSseProxies.builder(scanner).httpClient(client).build();
        try {
            var incoming = request(Map.of("Authorization", "Bearer A"));
            when(incoming.getUri()).thenReturn("/mcp");
            var reconnected = new java.util.concurrent.atomic.AtomicBoolean();
            when(incoming.getHeaders()).thenAnswer(call -> {
                if (reconnected.compareAndSet(false, true)) {
                    scanner.connect(new com.mcpscanner.client.McpServerConfig("https://server-b.example/mcp",
                            TransportType.MODERN_HTTP, () -> Map.of("Authorization", "Bearer B")));
                }
                return Map.of("Authorization", "Bearer A", "content-length", "58");
            });
            assertThat(proxy.serve(incoming).getStatus().getRequestStatus()).isEqualTo(409);
            assertThat(requests).hasSize(2);
            assertThat(requests).extracting(HttpRequest::uri).containsExactly(
                    URI.create("https://server-a.example/mcp"), URI.create("https://server-b.example/mcp"));
        } finally {
            proxy.stop();
            scanner.disconnect();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void completedReconnectRejectsBlockedProviderAcquisitionWithoutSubstitutingIdentityOrEndpoint() throws Exception {
        HttpClient client = mock(HttpClient.class);
        var requests = new java.util.concurrent.CopyOnWriteArrayList<HttpRequest>();
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenAnswer(call -> {
            requests.add(call.getArgument(0));
            return modernAdmission();
        });
        var entered = new java.util.concurrent.CompletableFuture<Void>();
        var release = new java.util.concurrent.CompletableFuture<Void>();
        var block = new java.util.concurrent.atomic.AtomicBoolean();
        com.mcpscanner.auth.AuthStrategy authA = () -> {
            if (block.get()) {
                entered.complete(null);
                release.join();
            }
            return Map.of("Authorization", "Bearer A");
        };
        var scanner = new McpScannerSession(client, McpEventLog.noop());
        scanner.connect(new com.mcpscanner.client.McpServerConfig("https://server-a.example/mcp", TransportType.MODERN_HTTP, authA));
        var proxy = TestSseProxies.builder(scanner).httpClient(client).build();
        var executor = java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            block.set(true);
            var incoming = request(proxy.auditHeaders(Map.of()),
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"demo\",\"arguments\":{}}}");
            when(incoming.getUri()).thenReturn("/mcp");
            var operation = executor.submit(() -> proxy.serve(incoming));
            entered.get(5, java.util.concurrent.TimeUnit.SECONDS);
            var reconnect = executor.submit(() -> {
                scanner.connect(new com.mcpscanner.client.McpServerConfig("https://server-b.example/mcp",
                        TransportType.MODERN_HTTP, () -> Map.of("Authorization", "Bearer B")));
            });
            reconnect.get(5, java.util.concurrent.TimeUnit.SECONDS);
            release.complete(null);
            assertThat(operation.get(5, java.util.concurrent.TimeUnit.SECONDS).getStatus().getRequestStatus()).isEqualTo(502);
            assertThat(requests).hasSize(2);
            assertThat(requests).allSatisfy(sent ->
                    assertThat(McpObjectMapper.INSTANCE.readTree(SseProxyServerTest.extractBody(sent)).path("method").asText())
                            .isEqualTo("server/discover"));

            var current = request(proxy.auditHeaders(Map.of()),
                    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"demo\",\"arguments\":{}}}");
            when(current.getUri()).thenReturn("/mcp");
            assertThat(proxy.serve(current).getStatus().getRequestStatus()).isEqualTo(200);
            assertThat(requests).hasSize(3);
            assertThat(requests.get(0).uri()).isEqualTo(URI.create("https://server-a.example/mcp"));
            assertThat(requests.get(0).headers().firstValue("Authorization")).contains("Bearer A");
            assertThat(requests.get(1).uri()).isEqualTo(URI.create("https://server-b.example/mcp"));
            assertThat(requests.get(1).headers().firstValue("Authorization")).contains("Bearer B");
            assertThat(requests.get(2).uri()).isEqualTo(URI.create("https://server-b.example/mcp"));
            assertThat(requests.get(2).headers().firstValue("Authorization")).contains("Bearer B");
            assertThat(McpObjectMapper.INSTANCE.readTree(SseProxyServerTest.extractBody(requests.get(2))).path("method").asText())
                    .isEqualTo("tools/call");
        } finally {
            release.complete(null);
            executor.shutdownNow();
            proxy.stop();
            scanner.disconnect();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    @SuppressWarnings("unchecked")
    void retiredRecoveryCannotMutateNewSessionHeadersBeforeOrDuringRefresh(boolean duringRefresh) throws Exception {
        HttpClient client = mock(HttpClient.class);
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(call -> modernAdmission());
        var authA = mock(com.mcpscanner.auth.AuthStrategy.class);
        when(authA.headers()).thenReturn(Map.of("X-Api-Key", "A"));
        when(authA.supportsRefresh()).thenReturn(true);
        var scanner = new McpScannerSession(client, McpEventLog.noop());
        Runnable reconnect = () -> scanner.connect(new com.mcpscanner.client.McpServerConfig(
                "https://server-b.example/mcp", TransportType.MODERN_HTTP, () -> Map.of("Authorization", "Bearer B")));
        when(authA.refresh()).thenAnswer(call -> {
            reconnect.run();
            return true;
        });
        try {
            scanner.connect(new com.mcpscanner.client.McpServerConfig("https://server-a.example/mcp", TransportType.MODERN_HTTP, authA));
            OperationRecovery oldRecovery = scanner.beginAuthOperation();
            if (!duringRefresh) reconnect.run();
            assertThat(oldRecovery.recover(new com.mcpscanner.core.protocol.McpFlow.HttpResponse(
                    401, Map.of(), "", true))).isEqualTo(RecoveryResult.STOP);
            verify(authA, times(duringRefresh ? 1 : 0)).refresh();
            assertThat(scanner.scannerHeaders()).containsEntry("Authorization", "Bearer B").doesNotContainKey("X-Api-Key");
        } finally { scanner.disconnect(); }
    }

    @ParameterizedTest
    @CsvSource({"false,false,Authorization,Bearer bob", "false,true,Authorization,Bearer bob",
            "true,false,Cookie,user=bob", "true,true,Cookie,user=bob"})
    void identityProbeOpensItsOwnStreamWithOnlyItsOwnCredentials(boolean managedAudit, boolean stripAuth,
                                                                  String credential, String identity) throws Exception {
        try (Server server = new Server(Stage.OPERATION, 401, 0)) {
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer alice"));
            when(scanner.beginAuthOperation()).thenReturn(mock(OperationRecovery.class));
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var headers = IdentityProbes.headers(proxy, managedAudit, Map.of(credential, identity));
                if (stripAuth) headers.putAll(ScannerSentinels.stripAuthOnly());
                var result = proxy.serve(request(headers));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(200);
                assertThat(McpObjectMapper.INSTANCE.readTree(result.getData()).path("id").asInt()).isEqualTo(1);
                assertThat(server.opens).isEqualTo(1);
                assertThat(server.requests).allSatisfy(sent -> {
                    assertThat(sent.headers().firstValue(credential)).contains(identity);
                    assertThat(sent.headers().firstValue("Authorization").orElse("")).isNotEqualTo("Bearer alice");
                    assertThat(sent.headers().map().keySet())
                            .noneMatch(name -> name.toLowerCase(java.util.Locale.ROOT).startsWith("x-mcp-scanner"));
                });
                verify(scanner, never()).beginAuthOperation();
            } finally { proxy.stop(); }
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void identityProbeChallengeIsReturnedWithoutPrimaryRecovery(boolean managedAudit) throws Exception {
        try (Server server = new Server(Stage.OPERATION, 401)) {
            McpScannerSession scanner = scanner();
            when(scanner.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer alice"));
            OperationRecovery recovery = mock(OperationRecovery.class);
            when(scanner.beginAuthOperation()).thenReturn(recovery);
            SseProxyServer proxy = TestSseProxies.builder(scanner).httpClient(server.client).build();
            try {
                var result = proxy.serve(request(IdentityProbes.headers(proxy, managedAudit, Map.of("Cookie", "user=bob"))));
                assertThat(result.getStatus().getRequestStatus()).isEqualTo(401);
                assertThat(server.opens).isEqualTo(1);
                verifyNoInteractions(recovery);
                verify(scanner, never()).beginAuthOperation();
            } finally { proxy.stop(); }
        }
    }


    private static WireResponse<InputStream> modernAdmission() {
        String admission = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"capabilities\":{},\"supportedVersions\":[\"2026-07-28\"]}}";
        return new WireResponse<>(200, new ByteArrayInputStream(admission.getBytes(StandardCharsets.UTF_8)),
                Map.of("Content-Type", List.of("application/json")));
    }

    private static McpScannerSession scanner() {
        McpScannerSession scanner = mock(McpScannerSession.class);
        when(scanner.resolvedEndpoint()).thenReturn("http://upstream/message");
        when(scanner.sseUrl()).thenReturn("http://upstream/sse");
        when(scanner.transportType()).thenReturn(TransportType.SSE);
        when(scanner.eventLog()).thenReturn(new McpEventLog(null));
        AtomicLong ids = new AtomicLong(100);
        when(scanner.nextRequestId()).thenAnswer(ignored -> ids.getAndIncrement());
        return scanner;
    }

    private static NanoHTTPD.IHTTPSession request(Map<String, String> headers) throws Exception {
        return request(headers, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}");
    }

    private static NanoHTTPD.IHTTPSession request(Map<String, String> headers, String requestBody) {
        var request = mock(NanoHTTPD.IHTTPSession.class);
        when(request.getMethod()).thenReturn(NanoHTTPD.Method.POST);
        when(request.getUri()).thenReturn("/message");
        ProxyRequestStubs.stubBody(request, headers, requestBody);
        return request;
    }

    enum Stage { OPEN, INITIALIZE, INITIALIZED, OPERATION }

    private static final class Server implements AutoCloseable {
        private final HttpClient client = mock(HttpClient.class);
        private final List<HttpRequest> requests = new java.util.concurrent.CopyOnWriteArrayList<>();
        private final List<SseScanSessionTest.QueueInputStream> streams = new java.util.concurrent.CopyOnWriteArrayList<>();
        private final Stage deniedStage;
        private final int deniedStatus;
        private final int deniedGenerations;
        private Map<Integer, Stage> deniedStages = Map.of();
        private Map<Integer, Integer> deniedStatuses = Map.of();
        private boolean holdFirstOperation;
        private String requiredOperationAuthorization;
        private String requiredSessionAuthorization;
        private final java.util.concurrent.CompletableFuture<Void> heldOperation = new java.util.concurrent.CompletableFuture<>();
        private int opens;
        private SseScanSessionTest.QueueInputStream stream;

        @SuppressWarnings("unchecked")
        private Server(Stage deniedStage, int deniedStatus) throws Exception {
            this(deniedStage, deniedStatus, Integer.MAX_VALUE);
        }

        @SuppressWarnings("unchecked")
        private Server(Stage deniedStage, int deniedStatus, int deniedGenerations) throws Exception {
            this.deniedGenerations = deniedGenerations;
            this.deniedStage = deniedStage;
            this.deniedStatus = deniedStatus;
            when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                    .thenAnswer(call -> respond(call.getArgument(0)));
        }

        private HttpResponse<?> respond(HttpRequest request) throws Exception {
            requests.add(request);
            if (requiredSessionAuthorization != null && !request.headers().firstValue("Authorization").orElse("").equals(requiredSessionAuthorization))
                return denial(request.method().equals("GET"));
            if (request.method().equals("GET")) {
                opens++;
                if (deniedStages.getOrDefault(opens, deniedStage) == Stage.OPEN && opens <= deniedGenerations) return denial(true);
                stream = new SseScanSessionTest.QueueInputStream();
                streams.add(stream);
                stream.push("event: endpoint\ndata: /message\n\n");
                return new WireResponse<>(200, stream, Map.of("Content-Type", List.of("text/event-stream")));
            }
            var envelope = McpObjectMapper.INSTANCE.readTree(SseProxyServerTest.extractBody(request));
            String method = envelope.path("method").asText();
            Stage stage = method.equals("initialize") ? Stage.INITIALIZE
                    : method.equals("notifications/initialized") ? Stage.INITIALIZED : Stage.OPERATION;
            if (stage == Stage.OPERATION && holdFirstOperation && !heldOperation.isDone()) {
                heldOperation.complete(null);
                return new WireResponse<>(202, "", Map.of());
            }
            if (deniedStages.getOrDefault(opens, deniedStage) == stage && opens <= deniedGenerations) return denial(false);
            if (stage == Stage.OPERATION && requiredOperationAuthorization != null
                    && !request.headers().firstValue("Authorization").orElse("").equals(requiredOperationAuthorization))
                return denial(false);
            if (stage == Stage.INITIALIZE || stage == Stage.OPERATION) {
                String result = stage == Stage.INITIALIZE
                        ? "{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"serverInfo\":{\"name\":\"fixture\",\"version\":\"1\"}}"
                        : "{}";
                stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":" + envelope.path("id")
                        + ",\"result\":" + result + "}\n\n");
            }
            return new WireResponse<>(202, "", Map.of());
        }

        private HttpResponse<?> denial(boolean inputStream) {
            String body = "{\"error\":\"denied\"}";
            Object entity = inputStream
                    ? new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)) : body;
            return new WireResponse<>(deniedStatuses.getOrDefault(opens, deniedStatus), entity, Map.of("WWW-Authenticate", List.of(CHALLENGE)));
        }

        public void close() { streams.forEach(SseScanSessionTest.QueueInputStream::close); }
    }

    private record WireResponse<T>(int statusCode, T body, HttpHeaders headers) implements HttpResponse<T> {
        private WireResponse(int status, T body, Map<String, List<String>> headers) {
            this(status, body, HttpHeaders.of(headers, (a, b) -> true));
        }
        public HttpRequest request() { return null; }
        public Optional<HttpResponse<T>> previousResponse() { return Optional.empty(); }
        public Optional<SSLSession> sslSession() { return Optional.empty(); }
        public URI uri() { return URI.create("http://upstream/sse"); }
        public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
    }
}
