package com.mcpscanner.proxy;

import com.mcpscanner.testutil.ProxyRequestStubs;

import burp.api.montoya.logging.Logging;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.logging.McpEventLog;
import fi.iki.elonen.NanoHTTPD;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class SseProxyHttpConnectionTest {
    @org.junit.jupiter.api.Test
    void managedResourceReadUsesCurrentSessionWithoutForwardingInternalHeaders() throws Exception {
        McpScannerSession session = mock(McpScannerSession.class);
        org.mockito.Mockito.lenient().when(session.isIssuedSessionId(org.mockito.ArgumentMatchers.anyString())).thenReturn(true);
        when(session.resolvedEndpoint()).thenReturn("https://upstream/mcp");
        when(session.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(session.eventLog()).thenReturn(new McpEventLog(null));
        when(session.protocolHeaders()).thenReturn(Map.of("Mcp-Session-Id", "current-session",
                "MCP-Protocol-Version", "2025-06-18"));
        when(session.prepareHttpOperation(any())).thenReturn(() -> new com.mcpscanner.core.protocol.McpFlow.HttpResponse(
                200, Map.of("Content-Type", "application/json"),
                "{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{\"contents\":[]}}", true));
        SseProxyServer proxy = TestSseProxies.builder(session).httpClient(mock(HttpClient.class)).build();
        try {
            Map<String, String> baseline = Map.of("mcp-session-id", "old-session",
                    "mcp-protocol-version", "2025-06-18");
            Map<String, String> headers = managedHeaders(proxy, baseline);
            var response = proxy.serve(request("{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"resources/read\",\"params\":{\"uri\":\"ui://widget/site-builder.html\"}}", headers));
            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            var operation = org.mockito.ArgumentCaptor.forClass(com.mcpscanner.core.protocol.McpRequests.Request.class);
            verify(session).prepareHttpOperation(operation.capture());
            assertThat(operation.getValue().headers().keySet().stream()
                    .filter(name -> name.equalsIgnoreCase("Mcp-Session-Id"))).hasSize(1);
            assertThat(operation.getValue().headers().entrySet().stream()
                    .filter(header -> header.getKey().equalsIgnoreCase("Mcp-Session-Id"))
                    .map(Map.Entry::getValue)).containsExactly("current-session");
            assertThat(operation.getValue().headers().keySet()).noneMatch(name ->
                    name.equalsIgnoreCase(com.mcpscanner.mcp.ScannerSentinels.AUDIT_CAPABILITY_HEADER));
        } finally { proxy.stop(); }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({"true,200", "false,401", "true,401"})
    void scannerOperationUsesBoundedSharedAuthenticationRecovery(boolean refreshAllowed, int finalStatus) throws Exception {
        HttpClient http = mock(HttpClient.class);
        List<HttpRequest> requests = new ArrayList<>();
        AtomicReference<String> token = new AtomicReference<>("old");
        AuthStrategy auth = mock(AuthStrategy.class);
        when(auth.headers()).thenAnswer(ignored -> Map.of("Authorization", "Bearer " + token.get()));
        when(auth.supportsRefresh()).thenReturn(true);
        when(auth.refresh()).thenAnswer(ignored -> {
            if (refreshAllowed) token.set("new");
            return refreshAllowed;
        });
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenAnswer(call -> {
            HttpRequest request = call.getArgument(0);
            requests.add(request);
            if (requests.size() == 1) return response(200,
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"supportedVersions\":[\"2026-07-28\"],\"capabilities\":{}}}");
            return response(requests.size() == 2 ? 401 : finalStatus, "{\"result\":{}}");
        });
        Logging log = mock(Logging.class);
        McpScannerSession session = new McpScannerSession(http, new McpEventLog(null));
        session.connect(new McpServerConfig("https://upstream/mcp", TransportType.MODERN_HTTP, auth));
        HttpClient rawProxyHttp = mock(HttpClient.class);
        SseProxyServer proxy = TestSseProxies.builder(session).httpClient(rawProxyHttp).build();
        try {
            NanoHTTPD.Response result = proxy.serve(managedRequest(proxy, Map.of("X-Correlation", "trace", "Authorization", "Bearer stale-baked-token")));
            assertThat(result.getStatus().getRequestStatus()).isEqualTo(refreshAllowed ? finalStatus : 401);
            assertThat(requests).hasSize(refreshAllowed ? 3 : 2);
            assertThat(requests.get(1).headers().firstValue("Authorization")).contains("Bearer old");
            HttpRequest last = requests.get(requests.size() - 1);
            assertThat(last.headers().firstValue("Authorization")).contains(refreshAllowed ? "Bearer new" : "Bearer old");
            assertThat(last.headers().firstValue("X-Correlation")).contains("trace");
            assertThat(last.headers().firstValue("Mcp-Method")).contains("tools/call");
            verify(auth).refresh();
            verifyNoInteractions(rawProxyHttp);
        } finally { proxy.stop(); session.disconnect(); }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(ints = {401, 403})
    void anonymousProbeDoesNotReadCredentialsOrRecover(int deniedStatus) throws Exception {
        HttpClient http = mock(HttpClient.class);
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(call -> response(deniedStatus, "denied"));
        McpScannerSession session = mock(McpScannerSession.class);
        org.mockito.Mockito.lenient().when(session.isIssuedSessionId(org.mockito.ArgumentMatchers.anyString())).thenReturn(true);
        when(session.resolvedEndpoint()).thenReturn("https://upstream/mcp");
        when(session.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(session.eventLog()).thenReturn(new McpEventLog(null));
        when(session.protocolHeaders()).thenReturn(Map.of("Mcp-Session-Id", "legacy-session", "Mcp-Protocol-Version", "2025-11-25"));
        SseProxyServer proxy = TestSseProxies.builder(session).httpClient(http).build();
        try {
            NanoHTTPD.Response result = proxy.serve(request(Map.of(
                    com.mcpscanner.mcp.ScannerSentinels.STRIP_AUTH_HEADER, "1",
                    "Authorization", "Bearer forged")));
            assertThat(result.getStatus().getRequestStatus()).isEqualTo(deniedStatus);
            var sent = org.mockito.ArgumentCaptor.forClass(HttpRequest.class);
            verify(http).send(sent.capture(), any());
            assertThat(sent.getValue().headers().firstValue("Authorization")).contains("Bearer forged");
            assertThat(sent.getValue().headers().firstValue("Mcp-Session-Id")).isEmpty();
            assertThat(sent.getValue().headers().firstValue("Mcp-Protocol-Version")).contains("2025-11-25");
            verify(session, never()).scannerHeaders();
            verify(session, never()).sendHttpOperation(any());
        } finally { proxy.stop(); }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {true, false})
    void insufficientScopeUsesSharedApprovalAndNeverLegacyRefresh(boolean approved) throws Exception {
        java.util.concurrent.atomic.AtomicInteger operations = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicInteger recoveries = new java.util.concurrent.atomic.AtomicInteger();
        AtomicReference<String> token = new AtomicReference<>("old");
        var credentials = new com.mcpscanner.core.connection.CredentialProvider() {
            public Map<String, String> headers() { return Map.of("Authorization", "Bearer " + token.get()); }
            public com.mcpscanner.core.connection.OperationRecovery beginOperation(String id) {
                return challenge -> {
                    assertThat(challenge.status()).isEqualTo(403);
                    assertThat(challenge.headers().entrySet()).anySatisfy(header -> {
                        assertThat(header.getKey()).isEqualToIgnoringCase("WWW-Authenticate");
                        assertThat(header.getValue()).isEqualTo("Bearer error=\"insufficient_scope\", scope=\"write\"");
                    });
                    recoveries.incrementAndGet();
                    if (!approved) return com.mcpscanner.core.connection.RecoveryResult.STOP;
                    token.set("approved");
                    return com.mcpscanner.core.connection.RecoveryResult.RETRY;
                };
            }
        };
        AuthStrategy auth = mock(AuthStrategy.class);
        when(auth.headers()).thenAnswer(ignored -> credentials.headers());
        when(auth.sharedCredentialProvider()).thenReturn(java.util.Optional.of(credentials));
        HttpClient http = mock(HttpClient.class);
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenAnswer(call -> {
            HttpRequest sent = call.getArgument(0);
            if (sent.headers().firstValue("Mcp-Method").orElse("").equals("server/discover"))
                return response(200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"supportedVersions\":[\"2026-07-28\"],\"capabilities\":{}}}");
            operations.incrementAndGet();
            if (sent.headers().firstValue("Authorization").orElse("").equals("Bearer approved")) return response(200, "ok");
            HttpResponse<InputStream> denied = response(403, "denied");
            when(denied.headers()).thenReturn(HttpHeaders.of(Map.of("WWW-Authenticate", List.of("Bearer error=\"insufficient_scope\", scope=\"write\"")), (a,b) -> true));
            return denied;
        });
        Logging log = mock(Logging.class);
        McpScannerSession session = new McpScannerSession(http, new McpEventLog(null));
        session.connect(new McpServerConfig("https://upstream/mcp", TransportType.MODERN_HTTP, auth));
        SseProxyServer proxy = TestSseProxies.builder(session).httpClient(mock(HttpClient.class)).build();
        try {
            var result = proxy.serve(managedRequest(proxy, Map.of()));
            assertThat(result.getStatus().getRequestStatus()).isEqualTo(approved ? 200 : 403);
            assertThat(operations.get()).isEqualTo(approved ? 2 : 1);
            assertThat(recoveries.get()).isEqualTo(1);
            verify(auth, never()).refresh();
        } finally { proxy.stop(); session.disconnect(); }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({"false,true", "true,true", "false,false", "true,false"})
    void legacySessionLossReinitializesOnceWithSameVersion(boolean afterAuthRefresh, boolean recovered) throws Exception {
        HttpClient http = mock(HttpClient.class);
        List<HttpRequest> sent = new ArrayList<>();
        java.util.concurrent.atomic.AtomicInteger initializes = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicInteger operations = new java.util.concurrent.atomic.AtomicInteger();
        AtomicReference<String> token = new AtomicReference<>("old");
        AuthStrategy auth = mock(AuthStrategy.class);
        when(auth.headers()).thenAnswer(ignored -> Map.of("Authorization", "Bearer " + token.get()));
        lenient().when(auth.supportsRefresh()).thenReturn(true);
        lenient().when(auth.refresh()).thenAnswer(ignored -> { token.set("new"); return true; });
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenAnswer(call -> {
            HttpRequest outgoing = call.getArgument(0);
            sent.add(outgoing);
            String body = SseProxyServerTest.extractBody(outgoing);
            if (body.contains("\"method\":\"initialize\"")) {
                int initialize = initializes.incrementAndGet();
                var admitted = response(200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"serverInfo\":{\"name\":\"fixture\",\"version\":\"1\"}}}");
                when(admitted.headers()).thenReturn(HttpHeaders.of(Map.of("Mcp-Session-Id", List.of("session-" + initialize)), (a,b) -> true));
                return admitted;
            }
            if (body.contains("notifications/initialized")) return response(202, "");
            int operation = operations.incrementAndGet();
            if (afterAuthRefresh && operation == 1) return response(401, "denied");
            if (initializes.get() == 1) return response(404, "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600}}");
            return response(recovered ? 200 : 404, "ok");
        });
        Logging log = mock(Logging.class);
        McpScannerSession session = new McpScannerSession(http, new McpEventLog(null));
        session.connect(new McpServerConfig("https://upstream/mcp", TransportType.STREAMABLE_HTTP, auth));
        SseProxyServer proxy = TestSseProxies.builder(session).httpClient(mock(HttpClient.class)).build();
        try {
            var result = proxy.serve(managedRequest(proxy, Map.of("Mcp-Session-Id", "session-1")));
            assertThat(result.getStatus().getRequestStatus()).isEqualTo(recovered ? 200 : 404);
            assertThat(initializes.get()).isEqualTo(2);
            assertThat(operations.get()).isEqualTo(afterAuthRefresh ? 3 : 2);
            assertThat(sent.get(sent.size() - 1).headers().firstValue("Mcp-Session-Id")).contains("session-2");
            assertThat(sent.get(sent.size() - 1).headers().firstValue("Mcp-Protocol-Version")).contains("2025-11-25");
            assertThat(sent).noneMatch(r -> r.headers().firstValue("Mcp-Method").isPresent());
        } finally { proxy.stop(); session.disconnect(); }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.EnumSource(value = TransportType.class, names = {"MODERN_HTTP", "STREAMABLE_HTTP"})
    void malformedScannerBodyRetainsCanonicalHttpHeaders(TransportType transport) throws Exception {
        McpScannerSession session = mock(McpScannerSession.class);
        org.mockito.Mockito.lenient().when(session.isIssuedSessionId(org.mockito.ArgumentMatchers.anyString())).thenReturn(true);
        when(session.resolvedEndpoint()).thenReturn("https://upstream/mcp");
        when(session.transportType()).thenReturn(transport);
        when(session.eventLog()).thenReturn(new McpEventLog(null));
        String version = transport == TransportType.MODERN_HTTP ? "2026-07-28" : "2025-11-25";
        when(session.protocolHeaders()).thenReturn(Map.of("MCP-Protocol-Version", version));
        when(session.prepareHttpOperation(any())).thenReturn(() -> new com.mcpscanner.core.protocol.McpFlow.HttpResponse(
                400, Map.of("Content-Type", "application/json"), "invalid-json", true));
        HttpClient raw = mock(HttpClient.class);
        SseProxyServer proxy = TestSseProxies.builder(session).httpClient(raw).build();
        try {
            var result = proxy.serve(request("not json", managedHeaders(proxy, Map.of("MCP-Protocol-Version", "stale", "Mcp-Method", "tools/call",
                    com.mcpscanner.mcp.ScannerSentinels.FRAMED_OPERATION_HEADER, com.mcpscanner.mcp.FramedOperation.encode(
                            Map.of("MCP-Protocol-Version", "stale", "Mcp-Method", "tools/call"))))));
            assertThat(result.getStatus().getRequestStatus()).isEqualTo(400);
            var operation = org.mockito.ArgumentCaptor.forClass(com.mcpscanner.core.protocol.McpRequests.Request.class);
            verify(session).prepareHttpOperation(operation.capture());
            assertThat(operation.getValue().body()).isEqualTo("not json");
            assertThat(operation.getValue().headers()).containsEntry("Content-Type", "application/json")
                    .containsEntry("Accept", "application/json, text/event-stream")
                    .containsEntry("MCP-Protocol-Version", version);
            verifyNoInteractions(raw);
        } finally { proxy.stop(); }
    }

    @org.junit.jupiter.api.Test
    void reconnectCompletesWhileProxyScopeApprovalIsPending() throws Exception {
        var approvalEntered = new java.util.concurrent.CompletableFuture<Void>();
        var approve = new java.util.concurrent.CompletableFuture<Void>();
        var requests = new java.util.concurrent.CopyOnWriteArrayList<HttpRequest>();
        var credentials = new com.mcpscanner.core.connection.CredentialProvider() {
            public Map<String, String> headers() { return Map.of("Authorization", "Bearer A"); }
            public com.mcpscanner.core.connection.OperationRecovery beginOperation(String id) {
                return challenge -> {
                    approvalEntered.complete(null);
                    approve.join();
                    return com.mcpscanner.core.connection.RecoveryResult.RETRY;
                };
            }
        };
        AuthStrategy auth = mock(AuthStrategy.class);
        when(auth.headers()).thenAnswer(ignored -> credentials.headers());
        when(auth.sharedCredentialProvider()).thenReturn(java.util.Optional.of(credentials));
        HttpClient http = mock(HttpClient.class);
        when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenAnswer(call -> {
            HttpRequest sent = call.getArgument(0);
            requests.add(sent);
            if (sent.headers().firstValue("Mcp-Method").orElse("").equals("server/discover"))
                return response(200, "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"supportedVersions\":[\"2026-07-28\"],\"capabilities\":{}}}");
            return response(403, "denied");
        });
        Logging log = mock(Logging.class);
        McpScannerSession session = new McpScannerSession(http, new McpEventLog(null));
        session.connect(new McpServerConfig("https://upstream/mcp", TransportType.MODERN_HTTP, auth));
        SseProxyServer proxy = TestSseProxies.builder(session).httpClient(mock(HttpClient.class)).build();
        var workers = java.util.concurrent.Executors.newFixedThreadPool(2);
        var incoming = managedRequest(proxy, Map.of());
        try {
            var oldOperation = java.util.concurrent.CompletableFuture.supplyAsync(() -> proxy.serve(incoming), workers);
            approvalEntered.get(3, java.util.concurrent.TimeUnit.SECONDS);
            var reconnect = java.util.concurrent.CompletableFuture.runAsync(() -> session.connect(
                    new McpServerConfig("https://upstream/mcp", TransportType.MODERN_HTTP,
                            new com.mcpscanner.auth.BearerTokenAuthStrategy("B"))), workers);
            reconnect.get(3, java.util.concurrent.TimeUnit.SECONDS);
            approve.complete(null);

            assertThat(oldOperation.get(3, java.util.concurrent.TimeUnit.SECONDS).getStatus().getRequestStatus())
                    .isEqualTo(502);
            assertThat(session.scannerHeaders()).containsEntry("Authorization", "Bearer B");
            assertThat(requests).hasSize(3);
            assertThat(requests.get(1).headers().firstValue("Authorization")).contains("Bearer A");
            assertThat(requests.get(2).headers().firstValue("Authorization")).contains("Bearer B");
        } finally {
            approve.complete(null);
            workers.shutdownNow();
            proxy.stop();
            session.disconnect();
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({"MODERN_HTTP,false", "MODERN_HTTP,true", "STREAMABLE_HTTP,false", "STREAMABLE_HTTP,true"})
    void manualHttpIdentityNeverUsesManagedCredentialsOrRecovery(TransportType transport, boolean retainedMarker) throws Exception {
        HttpClient managed = mock(HttpClient.class);
        HttpClient isolated = mock(HttpClient.class);
        var managedRequests = new ArrayList<HttpRequest>();
        var manualRequests = new ArrayList<HttpRequest>();
        when(managed.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenAnswer(call -> {
            HttpRequest sent = call.getArgument(0);
            managedRequests.add(sent);
            String body = SseProxyServerTest.extractBody(sent);
            if (body.contains("server/discover")) return response(200,
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"supportedVersions\":[\"2026-07-28\"],\"capabilities\":{}}}");
            if (body.contains("initialize") && !body.contains("notifications")) {
                var initialized = response(200,
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"serverInfo\":{\"name\":\"test\",\"version\":\"1\"}}}");
                when(initialized.headers()).thenReturn(HttpHeaders.of(Map.of("Mcp-Session-Id", List.of("session-A")), (a,b) -> true));
                return initialized;
            }
            return response(body.contains("notifications") ? 202 : 200, "{}");
        });
        when(isolated.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenAnswer(call -> {
            manualRequests.add(call.getArgument(0));
            return response(401, "denied");
        });
        AuthStrategy auth = mock(AuthStrategy.class);
        when(auth.headers()).thenReturn(Map.of("Authorization", "Bearer A"));
        Logging log = mock(Logging.class);
        McpScannerSession session = new McpScannerSession(managed, new McpEventLog(null));
        session.connect(new McpServerConfig("https://upstream/mcp", transport, auth));
        SseProxyServer proxy = TestSseProxies.builder(session).httpClient(isolated).build();
        try {
            var baseline = new java.util.HashMap<>(Map.of("Authorization", "Bearer stale"));
            baseline.putAll(proxy.captureScanConnection().headers(baseline));
            baseline.remove("Authorization");
            assertThat(proxy.serve(request(baseline)).getStatus().getRequestStatus()).isEqualTo(200);
            int managedCount = managedRequests.size();
            for (var identity : List.of(Map.of("Authorization", "Bearer B"), Map.<String, String>of(),
                    Map.of("X-Api-Key", "B"), com.mcpscanner.mcp.ScannerSentinels.stripAuthOnly(),
                    com.mcpscanner.mcp.ScannerSentinels.withStripAuth("Authorization", "Bearer forged"))) {
                var manual = new java.util.HashMap<>(identity);
                if (retainedMarker) manual.putAll(proxy.auditHeaders(Map.of("Cookie", "session=original")));
                assertThat(proxy.serve(request(manual)).getStatus().getRequestStatus()).isEqualTo(401);
            }
            assertThat(managedRequests).hasSize(managedCount);
            assertThat(managedRequests.get(managedCount - 1).headers().firstValue("Authorization")).contains("Bearer A");
            assertThat(manualRequests).hasSize(5);
            assertThat(manualRequests).allSatisfy(sent ->
                    assertThat(sent.headers().firstValue("Mcp-Session-Id")).isEmpty());
            assertThat(manualRequests.get(3).headers().firstValue("Authorization")).isEmpty();
            assertThat(manualRequests.get(4).headers().firstValue("Authorization")).contains("Bearer forged");
            assertThat(manualRequests.get(0).headers().firstValue("Authorization")).contains("Bearer B");
            assertThat(manualRequests.get(1).headers().firstValue("Authorization")).isEmpty();
            assertThat(manualRequests.get(2).headers().firstValue("Authorization")).isEmpty();
            assertThat(manualRequests.get(2).headers().firstValue("X-Api-Key")).contains("B");
            assertThat(manualRequests).allSatisfy(sent ->
                    assertThat(sent.headers().firstValue(com.mcpscanner.mcp.ScannerSentinels.AUDIT_CAPABILITY_HEADER)).isEmpty());
            verify(auth, never()).refresh();
        } finally { proxy.stop(); session.disconnect(); }
    }

    private static Map<String, String> managedHeaders(SseProxyServer proxy, Map<String, String> baseline) {
        var headers = new java.util.HashMap<>(baseline);
        headers.putAll(proxy.captureScanConnection().headers(baseline));
        headers.keySet().removeIf("Authorization"::equalsIgnoreCase);
        return headers;
    }

    private static NanoHTTPD.IHTTPSession managedRequest(SseProxyServer proxy, Map<String, String> baseline) throws Exception {
        return request(managedHeaders(proxy, baseline));
    }

    private static NanoHTTPD.IHTTPSession request(Map<String, String> headers) throws Exception {
        return request("{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{}}}", headers);
    }

    private static NanoHTTPD.IHTTPSession request(String requestBody, Map<String, String> headers) throws Exception {
        NanoHTTPD.IHTTPSession request = mock(NanoHTTPD.IHTTPSession.class);
        when(request.getMethod()).thenReturn(NanoHTTPD.Method.POST);
        when(request.getUri()).thenReturn("/mcp");
        ProxyRequestStubs.stubBody(request, headers, requestBody);
        return request;
    }

    private static HttpResponse<InputStream> response(int status, String body) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(status);
        when(response.headers()).thenReturn(HttpHeaders.of(Map.of("Content-Type", List.of("application/json")), (a, b) -> true));
        when(response.body()).thenReturn(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        return response;
    }
}
