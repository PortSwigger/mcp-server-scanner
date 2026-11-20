package com.mcpscanner.proxy;

import com.mcpscanner.testutil.ProxyRequestStubs;

import com.mcpscanner.config.RedirectMode;

import burp.api.montoya.logging.Logging;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.logging.McpEventLog;
import fi.iki.elonen.NanoHTTPD;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import com.mcpscanner.mcp.ScannerSentinels;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.time.Duration;

import static com.mcpscanner.testutil.OpenedStreams.openedByAGet;
import static com.mcpscanner.testutil.AwaitedFutures.doneWithin;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import org.mockito.ArgumentCaptor;

@ExtendWith(MockitoExtension.class)
class SseProxyServerTest {

    @Mock private McpScannerSession scannerSession;
    @Mock private Logging logging;

    private McpEventLog eventLog;

    @BeforeEach
    void stubEventLog() {
        eventLog = new McpEventLog(logging);
        lenient().when(scannerSession.eventLog()).thenReturn(eventLog);
    }

    @ParameterizedTest
    @ValueSource(strings = {"initialize", "notifications/initialized"})
    @SuppressWarnings("unchecked")
    void sseHandshakeRefusalsAreRelayedVerbatimAndKeptOutOfLogs(String failingStage)
            throws Exception {
        String bearer = "Bearer private-access-token";
        String hostileBody = bearer + " \"hostile-response\"\nforged log entry";
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/message");
        when(scannerSession.sseUrl()).thenReturn("http://upstream/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        AtomicLong ids = new AtomicLong(100);
        when(scannerSession.nextRequestId()).thenAnswer(invocation -> ids.getAndIncrement());
        SseScanSessionTest.QueueInputStream stream = new SseScanSessionTest.QueueInputStream();
        stream.push("event: endpoint\ndata: /message\n\n");
        HttpResponse<InputStream> opened = mockStreamResponse(200, "text/event-stream", "");
        when(opened.body()).thenReturn(stream);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if (request.method().equals("GET")) return opened;
                    var body = com.mcpscanner.mcp.McpObjectMapper.INSTANCE.readTree(extractBody(request));
                    boolean failed = body.path("method").asText().equals(failingStage);
                    if (body.has("id") && !failed) {
                        stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":"
                                + body.get("id") + ",\"result\":{}}\n\n");
                    }
                    HttpResponse<String> response = mock(HttpResponse.class);
                    when(response.statusCode()).thenReturn(failed ? 500 : 202);
                    when(response.body()).thenReturn(failed ? hostileBody : "");
                    return response;
                });
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession(
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
                    Map.of("Authorization", bearer)));
            assertThat(response.getStatus().getRequestStatus()).isEqualTo(500);
            assertThat(new String(response.getData().readAllBytes(), StandardCharsets.UTF_8)).isEqualTo(hostileBody);
            assertThat(eventLog.snapshot()).extracting(McpEventLog.LogEntry::message)
                    .allSatisfy(message -> assertThat(message)
                            .doesNotContain(bearer, "hostile-response", "forged log entry"));
        } finally {
            proxy.stop();
        }
    }

    @Test
    void startsAndStopsWithoutError() throws Exception {
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).build();
        proxy.start();
        assertThat(proxy.port()).isGreaterThan(0);
        proxy.stop();
    }

    @Test
    void boundedProxyRejectsPostWithoutContentLengthBeforeReading() throws Exception {
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        HttpClient httpClient = mock(HttpClient.class);
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).postBodyLimit(2L).build();
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}");
        when(session.getHeaders()).thenReturn(Map.of());

        NanoHTTPD.Response response = proxy.serve(session);

        assertThat(response.getStatus().getRequestStatus()).isEqualTo(411);
        verify(session, never()).parseBody(any());
        verify(session, never()).getInputStream();
        verifyNoInteractions(httpClient);
    }

    @Test
    void acceptsPostBodyExactlyAtConfiguredLimitWithContentLength() throws Exception {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.protocolHeaders()).thenReturn(Map.of());
        when(scannerSession.credentialHeaderNames()).thenReturn(java.util.Set.of());
        when(scannerSession.prepareHttpOperation(any())).thenReturn(() ->
                new com.mcpscanner.core.protocol.McpFlow.HttpResponse(
                        200, Map.of("Content-Type", "application/json"), "{}", true));
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(mock(HttpClient.class)).postBodyLimit((long) body.getBytes(StandardCharsets.UTF_8).length).build();
        NanoHTTPD.IHTTPSession session = mockManagedSession(proxy, body);
        Map<String, String> headers = new java.util.HashMap<>(session.getHeaders());
        headers.put("content-length", Integer.toString(body.getBytes(StandardCharsets.UTF_8).length));
        when(session.getHeaders()).thenReturn(headers);
        when(session.getInputStream()).thenReturn(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));

        NanoHTTPD.Response response = proxy.serve(session);

        assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
        verify(session, never()).parseBody(any());
        verify(scannerSession).prepareHttpOperation(any());
    }

    @Test
    void rejectsDeclaredOversizePostBeforeReadingBody() throws Exception {
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        HttpClient httpClient = mock(HttpClient.class);
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).postBodyLimit(2L).build();
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}", Map.of("content-length", "3"));

        NanoHTTPD.Response response = proxy.serve(session);

        assertThat(response.getStatus().getRequestStatus()).isEqualTo(413);
        verify(session, never()).getInputStream();
        verify(session, never()).parseBody(any());
        verifyNoInteractions(httpClient);
    }

    @Test
    void unconfiguredProxyAppliesDefaultPostBodyLimit() throws Exception {
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        HttpClient httpClient = mock(HttpClient.class);
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        long overDefault = com.mcpscanner.config.ResourceCap.PROXY_POST_BODY_BYTES.defaultValue() + 1;
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}", Map.of("content-length", Long.toString(overDefault)));

        NanoHTTPD.Response response = proxy.serve(session);

        assertThat(response.getStatus().getRequestStatus()).isEqualTo(413);
        verify(session, never()).getInputStream();
        verify(session, never()).parseBody(any());
        verifyNoInteractions(httpClient);
    }

    @Test
    void boundedProxyRejectsUnsupportedChunkedBodyBeforeReading() throws Exception {
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        HttpClient httpClient = mock(HttpClient.class);
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).postBodyLimit(1024L).build();
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}", Map.of("transfer-encoding", "chunked"));

        NanoHTTPD.Response response = proxy.serve(session);

        assertThat(response.getStatus().getRequestStatus()).isEqualTo(411);
        verify(session, never()).getInputStream();
        verifyNoInteractions(httpClient);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    @SuppressWarnings("unchecked")
    void resetOrStopCancelsAnonymousHandshakeAndReleasesPermit(boolean stop) throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/message");
        when(scannerSession.sseUrl()).thenReturn("http://upstream/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        SseScanSessionTest.QueueInputStream stream = new SseScanSessionTest.QueueInputStream();
        HttpResponse<InputStream> response = openedByAGet(mock(HttpResponse.class));
        when(response.body()).thenReturn(stream);
        CompletableFuture<HttpRequest> opened = new CompletableFuture<>();
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    opened.complete(invocation.getArgument(0));
                    return response;
                });
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession request = mockIHttpSession(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
                ScannerSentinels.stripAuthOnly());
        CompletableFuture<NanoHTTPD.Response> result = CompletableFuture.supplyAsync(() -> proxy.serve(request));
        try {
            assertThat(doneWithin(opened, Duration.ofSeconds(1)).join().headers().map()).isEmpty();
            if (stop) {
                proxy.stop();
            } else {
                proxy.resetScanSession();
            }
            assertThat(doneWithin(result, Duration.ofSeconds(1)).join().getStatus().getRequestStatus()).isEqualTo(502);
            assertThat(proxy.concurrencyPermitsAvailable()).isEqualTo(32);
        } finally {
            stream.close();
            proxy.stop();
        }
    }

    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    @SuppressWarnings("unchecked")
    void resetOrStopCancelsStalledOperationPostAndReleasesPermit(boolean stop, boolean stalledBody)
            throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/message");
        when(scannerSession.sseUrl()).thenReturn("http://upstream/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        AtomicLong ids = new AtomicLong(100);
        when(scannerSession.nextRequestId()).thenAnswer(invocation -> ids.getAndIncrement());
        SseScanSessionTest.QueueInputStream stream = new SseScanSessionTest.QueueInputStream();
        stream.push("event: endpoint\ndata: /message?session=anonymous\n\n");
        HttpResponse<InputStream> opened = mockStreamResponse(200, "text/event-stream", "");
        when(opened.body()).thenReturn(stream);
        CompletableFuture<Void> operationStarted = new CompletableFuture<>();
        CompletableFuture<Void> releasePost = new CompletableFuture<>();
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if (request.method().equals("GET")) return opened;
                    var body = com.mcpscanner.mcp.McpObjectMapper.INSTANCE.readTree(extractBody(request));
                    HttpResponse<String> response = mock(HttpResponse.class);
                    lenient().when(response.statusCode()).thenReturn(202);
                    if (body.path("method").asText().equals("tools/list")) {
                        if (stalledBody) {
                            when(response.body()).thenAnswer(bodyInvocation -> {
                                operationStarted.complete(null);
                                releasePost.get();
                                return "";
                            });
                        } else {
                            operationStarted.complete(null);
                            releasePost.get();
                        }
                    } else {
                        when(response.body()).thenReturn("");
                        if (body.has("id")) {
                            stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":"
                                    + body.get("id") + ",\"result\":{}}\n\n");
                        }
                    }
                    return response;
                });
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        var request = mockIHttpSession("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
                ScannerSentinels.stripAuthOnly());
        CompletableFuture<NanoHTTPD.Response> result = CompletableFuture.supplyAsync(() -> proxy.serve(request));
        try {
            doneWithin(operationStarted, Duration.ofSeconds(1));
            if (stop) proxy.stop();
            else proxy.resetScanSession();
            assertThat(doneWithin(result, Duration.ofSeconds(1)).join().getStatus().getRequestStatus()).isEqualTo(502);
            assertThat(proxy.concurrencyPermitsAvailable()).isEqualTo(32);
        } finally {
            releasePost.complete(null);
            stream.close();
            proxy.stop();
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {401, 403})
    @SuppressWarnings("unchecked")
    void strippedSseProbeOpensReplacementIdentityStreamAndPreservesDenial(int status) throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        SseScanSession authenticated = mock(SseScanSession.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/message");
        when(scannerSession.sseUrl()).thenReturn("http://upstream/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        HttpResponse<InputStream> denial = mockStreamResponse(status, "application/json", "{\"error\":\"denied\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(denial);
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).managedSessions(authenticated).build();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession(
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
                    Map.of(ScannerSentinels.STRIP_AUTH_HEADER.toLowerCase(), "true",
                            "authorization", "Bearer scanner-token", "x-api-key", "secret")));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(status);
            assertThat(new String(response.getData().readAllBytes(), StandardCharsets.UTF_8))
                    .isEqualTo("{\"error\":\"denied\"}");
            ArgumentCaptor<HttpRequest> requests = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient).send(requests.capture(), any());
            assertThat(requests.getValue().method()).isEqualTo("GET");
            assertThat(requests.getValue().headers().firstValue("Authorization")).contains("Bearer scanner-token");
            assertThat(requests.getValue().headers().firstValue("X-Api-Key")).contains("secret");
            verifyNoInteractions(authenticated);
        } finally {
            proxy.stop();
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {200, 401})
    @SuppressWarnings("unchecked")
    void strippedSseProbeKeepingTheSessionPostsOnTheLiveStreamWithoutRecoveryOrRetirement(int status)
            throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        SseScanSession live = mock(SseScanSession.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/message?session=live");
        when(scannerSession.sseUrl()).thenReturn("http://upstream/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(live.forwardRequest(anyString(), anyMap()))
                .thenReturn(new ProxyResponse(status, "application/json", "{\"result\":\"live-stream\"}"));
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).managedSessions(live).build();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession(
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
                    Map.of(ScannerSentinels.STRIP_AUTH_HEADER, ScannerSentinels.SENTINEL_VALUE,
                            ScannerSentinels.KEEP_SESSION_HEADER, ScannerSentinels.SENTINEL_VALUE)));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(status);
            ArgumentCaptor<Map<String, String>> forwarded = ArgumentCaptor.forClass(Map.class);
            verify(live).forwardRequest(anyString(), forwarded.capture());
            assertThat(forwarded.getValue().keySet())
                    .anyMatch(ScannerSentinels.STRIP_AUTH_HEADER::equalsIgnoreCase);
            verify(live, never()).close();
            verify(scannerSession, never()).beginAuthOperation();
            verifyNoInteractions(httpClient);
        } finally {
            proxy.stop();
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {401, 403})
    @SuppressWarnings("unchecked")
    void anonymousSseProbePreservesInitializeDenialWithoutRefresh(int status) throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/message");
        when(scannerSession.sseUrl()).thenReturn("http://upstream/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        SseScanSessionTest.QueueInputStream stream = new SseScanSessionTest.QueueInputStream();
        stream.push("event: endpoint\ndata: /message?session=anonymous\n\n");
        HttpResponse<InputStream> opened = mockStreamResponse(200, "text/event-stream", "");
        when(opened.body()).thenReturn(stream);
        HttpResponse<String> denial = mock(HttpResponse.class);
        when(denial.statusCode()).thenReturn(status);
        when(denial.body()).thenReturn("{\"error\":\"handshake denied\"}");
        when(denial.headers()).thenReturn(HttpHeaders.of(Map.of(), (a, b) -> true));
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> ((HttpRequest) invocation.getArgument(0)).method().equals("GET")
                        ? opened : denial);
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession(
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}",
                    ScannerSentinels.stripAuthOnly()));
            assertThat(response.getStatus().getRequestStatus()).isEqualTo(status);
            assertThat(new String(response.getData().readAllBytes(), StandardCharsets.UTF_8))
                    .isEqualTo("{\"error\":\"handshake denied\"}");
            verify(httpClient, times(2)).send(any(), any());
        } finally {
            proxy.stop();
            stream.close();
        }
    }

    @ParameterizedTest
    @CsvSource({"200,false,tools/list", "200,true,tools/list", "401,false,tools/list", "403,false,tools/list",
            "200,false,tools/call", "200,true,tools/call", "401,false,tools/call", "403,false,tools/call"})
    @SuppressWarnings("unchecked")
    void anonymousSseProbeIsolatesHandshakeAndPreservesExplicitOperationAuth(int operationStatus,
                                                                            boolean forgedAuth,
                                                                            String method) throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        SseScanSession authenticated = mock(SseScanSession.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/message?session=authenticated");
        when(scannerSession.sseUrl()).thenReturn("http://upstream/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        AtomicLong ids = new AtomicLong(100);
        when(scannerSession.nextRequestId()).thenAnswer(invocation -> ids.getAndIncrement());
        when(authenticated.forwardRequest(anyString(), anyMap()))
                .thenReturn(new ProxyResponse(200, "application/json", "{\"result\":\"authenticated\"}"));
        SseScanSessionTest.QueueInputStream stream = spy(new SseScanSessionTest.QueueInputStream());
        stream.push("event: endpoint\ndata: /message?session=anonymous\n\n");
        HttpResponse<InputStream> opened = mockStreamResponse(200, "text/event-stream", "");
        when(opened.body()).thenReturn(stream);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if (request.method().equals("GET")) return opened;
                    var body = com.mcpscanner.mcp.McpObjectMapper.INSTANCE.readTree(extractBody(request));
                    boolean operation = body.path("method").asText().equals(method);
                    int status = operation ? operationStatus : 202;
                    if (body.has("id") && status < 300) {
                        String result = operation
                                ? "{\"content\":[{\"type\":\"text\",\"text\":\"protected-document\"}]}" : "{}";
                        stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":"
                                + body.get("id") + ",\"result\":" + result + "}\n\n");
                    }
                    HttpResponse<String> response = mock(HttpResponse.class);
                    when(response.statusCode()).thenReturn(status);
                    when(response.body()).thenReturn(status >= 400 ? "{\"error\":\"denied\"}" : "");
                    if (status == 401 || status == 403)
                        when(response.headers()).thenReturn(HttpHeaders.of(Map.of(), (a, b) -> true));
                    return response;
                });
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).managedSessions(authenticated).build();
        String requestBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + method
                + "\",\"params\":{\"name\":\"read_protected_document\",\"arguments\":{}}}";
        try {
            assertThat(proxy.serve(mockManagedSession(proxy, requestBody)).getStatus().getRequestStatus()).isEqualTo(200);
            clearInvocations(scannerSession);
            Map<String, String> probeHeaders = forgedAuth
                    ? ScannerSentinels.withStripAuth("Authorization", "Bearer forged-token")
                    : ScannerSentinels.stripAuthOnly();
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession(requestBody, probeHeaders));
            assertThat(response.getStatus().getRequestStatus()).isEqualTo(operationStatus);
            String responseBody = new String(response.getData().readAllBytes(), StandardCharsets.UTF_8);
            assertThat(responseBody).contains(operationStatus == 200 ? "protected-document" : "denied");
            assertThat(responseBody).doesNotContain("authenticated");
            verify(scannerSession, never()).scannerHeaders();
            verify(scannerSession, never()).beginAuthOperation();
            assertThat(proxy.serve(mockManagedSession(proxy, requestBody)).getStatus().getRequestStatus()).isEqualTo(200);

            ArgumentCaptor<HttpRequest> requests = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(4)).send(requests.capture(), any());
            List<HttpRequest> sent = requests.getAllValues();
            assertThat(sent.get(0).method()).isEqualTo("GET");
            assertThat(sent.get(0).headers().firstValue("Authorization"))
                    .isEqualTo(forgedAuth ? Optional.of("Bearer forged-token") : Optional.empty());
            assertThat(sent.subList(1, 4)).allSatisfy(request ->
                    assertThat(request.uri().getQuery()).isEqualTo("session=anonymous"));
            assertThat(extractBody(sent.get(1))).contains("\"method\":\"initialize\"");
            assertThat(extractBody(sent.get(2))).contains("\"method\":\"notifications/initialized\"");
            assertThat(sent.subList(1, 3)).allSatisfy(request ->
                    assertThat(request.headers().firstValue("Authorization"))
                            .isEqualTo(forgedAuth ? Optional.of("Bearer forged-token") : Optional.empty()));
            assertThat(sent.get(3).headers().firstValue("Authorization"))
                    .isEqualTo(forgedAuth ? Optional.of("Bearer forged-token") : Optional.empty());
            assertThat(sent).allSatisfy(request ->
                    assertThat(request.headers().firstValue(ScannerSentinels.STRIP_AUTH_HEADER)).isEmpty());
            verify(authenticated, times(2)).forwardRequest(anyString(), anyMap());
            verify(authenticated, never()).close();
            verify(stream, atLeastOnce()).close();
            verify(scannerSession).scannerHeaders();
        } finally {
            proxy.stop();
            stream.close();
        }
    }

    @Test
    void servesSseTransportViaSseScanSession() throws Exception {
        SseScanSession sseScanSession = mock(SseScanSession.class);
        HttpClient httpClient = mock(HttpClient.class);
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).managedSessions(sseScanSession).build();

        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:8080/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.nextRequestId()).thenReturn(42L);

        String requestBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}";
        ProxyResponse expectedResponse =
                new ProxyResponse(200, "application/json", "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        when(sseScanSession.forwardRequest(anyString(), anyMap())).thenReturn(expectedResponse);

        NanoHTTPD.IHTTPSession session = mockManagedSession(proxy, requestBody);

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            String responseBody = new String(response.getData().readAllBytes());
            assertThat(responseBody).isEqualTo("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void serveSse_rewritesJsonRpcIdBeforeForwardingToSseScanSession() throws Exception {
        SseScanSession sseScanSession = mock(SseScanSession.class);
        HttpClient httpClient = mock(HttpClient.class);
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).managedSessions(sseScanSession).build();

        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:8080/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.nextRequestId()).thenReturn(7L, 8L, 9L);
        when(sseScanSession.forwardRequest(anyString(), anyMap())).thenReturn(
                new ProxyResponse(200, "application/json", "{}"));

        String originalBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}";

        proxy.start();
        try {
            proxy.serve(mockManagedSession(proxy, originalBody));
            proxy.serve(mockManagedSession(proxy, originalBody));
            proxy.serve(mockManagedSession(proxy, originalBody));

            ArgumentCaptor<String> bodyCaptor = ArgumentCaptor.forClass(String.class);
            verify(sseScanSession, times(3)).forwardRequest(bodyCaptor.capture(), anyMap());

            List<String> forwardedBodies = bodyCaptor.getAllValues();
            assertThat(forwardedBodies.get(0)).contains("\"id\":7").doesNotContain("\"id\":1");
            assertThat(forwardedBodies.get(1)).contains("\"id\":8").doesNotContain("\"id\":1");
            assertThat(forwardedBodies.get(2)).contains("\"id\":9").doesNotContain("\"id\":1");
        } finally {
            proxy.stop();
        }
    }

    @Test
    void stopClosesSseScanSession() throws Exception {
        SseScanSession sseScanSession = mock(SseScanSession.class);
        HttpClient httpClient = mock(HttpClient.class);
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).managedSessions(sseScanSession).build();
        cacheManagedSseSession(proxy, sseScanSession);

        proxy.start();
        proxy.stop();

        verify(sseScanSession).close();
    }

    @Test
    void closingScanSessionIoExceptionIsLogged() throws Exception {
        SseScanSession sseScanSession = mock(SseScanSession.class);
        HttpClient httpClient = mock(HttpClient.class);
        doThrow(new IOException("socket broken")).when(sseScanSession).close();
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).managedSessions(sseScanSession).build();
        cacheManagedSseSession(proxy, sseScanSession);

        proxy.resetScanSession();

        verify(logging).logToError(contains("socket broken"));
    }

    @Test
    void resetScanSessionClosesCachedSessionSoNextScanTargetsNewServer() throws Exception {
        SseScanSession firstSession = mock(SseScanSession.class);
        HttpClient httpClient = mock(HttpClient.class);
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).managedSessions(firstSession).build();

        String requestBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}";
        when(scannerSession.resolvedEndpoint()).thenReturn("http://first.example/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.nextRequestId()).thenReturn(42L);
        when(firstSession.forwardRequest(anyString(), anyMap())).thenReturn(
                new ProxyResponse(200, "application/json", "{}"));

        NanoHTTPD.IHTTPSession session = mockManagedSession(proxy, requestBody);

        proxy.start();
        try {
            proxy.serve(session);
            verify(firstSession).forwardRequest(anyString(), anyMap());

            proxy.resetScanSession();
            verify(firstSession).close();

            when(scannerSession.resolvedEndpoint()).thenReturn("http://second.example/sse");
            when(scannerSession.sseUrl()).thenReturn("http://second.example/sse");

            proxy.serve(mockManagedSession(proxy, requestBody));

            verifyNoMoreInteractions(firstSession);
        } finally {
            proxy.stop();
        }
    }

    @ParameterizedTest
    @EnumSource(value = RedirectMode.class, names = {"SAME_ORIGIN", "ALWAYS"})
    void redirectModeChangeRetiresCachedSseSessionBeforeNextForward(RedirectMode initialMode) throws Exception {
        SseScanSession firstSession = mock(SseScanSession.class);
        SseScanSession nextSession = mock(SseScanSession.class);
        java.util.concurrent.atomic.AtomicReference<RedirectMode> mode =
                new java.util.concurrent.atomic.AtomicReference<>(initialMode);
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(mock(HttpClient.class))
                .managedSessions(firstSession, nextSession).redirectMode(mode::get).build();
        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:8080/sse");
        when(scannerSession.sseUrl()).thenReturn("http://localhost:8080/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.nextRequestId()).thenReturn(7L, 8L);
        when(firstSession.forwardRequest(anyString(), anyMap())).thenReturn(
                new ProxyResponse(200, "application/json", "{}"));
        when(nextSession.forwardRequest(anyString(), anyMap())).thenReturn(
                new ProxyResponse(200, "application/json", "{}"));

        proxy.start();
        try {
            String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";
            proxy.serve(mockManagedSession(proxy, body));
            mode.set(RedirectMode.METHOD_PRESERVING_SAME_ORIGIN);
            proxy.serve(mockManagedSession(proxy, body));

            verify(firstSession).close();
            verify(firstSession, times(1)).forwardRequest(anyString(), anyMap());
            verify(nextSession, times(1)).forwardRequest(anyString(), anyMap());
        } finally {
            proxy.stop();
        }
    }

    private void cacheManagedSseSession(SseProxyServer proxy, SseScanSession managed) throws Exception {
        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:8080/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(managed.forwardRequest(anyString(), anyMap())).thenReturn(new ProxyResponse(200, "application/json", "{}"));
        proxy.serve(mockManagedSession(proxy, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}"));
    }

    private NanoHTTPD.IHTTPSession mockAnonymousHttpSession(String body) throws Exception {
        return mockIHttpSession(body, ScannerSentinels.stripAuthOnly());
    }

    private NanoHTTPD.IHTTPSession mockAnonymousHttpSession(String body, Map<String, String> headers)
            throws Exception {
        Map<String, String> anonymousHeaders = new java.util.HashMap<>(headers);
        anonymousHeaders.putAll(ScannerSentinels.stripAuthOnly());
        return mockIHttpSession(body, anonymousHeaders);
    }

    private NanoHTTPD.IHTTPSession mockAnonymousHttpSession(String body, NanoHTTPD.Method method,
                                                           String uri, String query) throws Exception {
        return mockIHttpSession(body, method, uri, query, ScannerSentinels.stripAuthOnly());
    }

    private NanoHTTPD.IHTTPSession mockManagedSession(SseProxyServer proxy, String body) throws Exception {
        return mockIHttpSession(body, proxy.auditHeaders(Map.of()));
    }

    private NanoHTTPD.IHTTPSession mockIHttpSession(String requestBody) throws Exception {
        return mockIHttpSession(requestBody, NanoHTTPD.Method.POST, pathFromConfiguredEndpoint(),
                queryFromConfiguredEndpoint(), Map.of());
    }

    private NanoHTTPD.IHTTPSession mockIHttpSession(String requestBody, Map<String, String> headers)
            throws Exception {
        return mockIHttpSession(requestBody, NanoHTTPD.Method.POST, pathFromConfiguredEndpoint(),
                queryFromConfiguredEndpoint(), headers);
    }

    private NanoHTTPD.IHTTPSession mockIHttpSession(String requestBody,
                                                    NanoHTTPD.Method method,
                                                    String uri,
                                                    String query) throws Exception {
        return mockIHttpSession(requestBody, method, uri, query, Map.of());
    }

    private NanoHTTPD.IHTTPSession mockIHttpSession(String requestBody,
                                                    NanoHTTPD.Method method,
                                                    String uri,
                                                    String query,
                                                    Map<String, String> headers) throws Exception {
        NanoHTTPD.IHTTPSession session = mock(NanoHTTPD.IHTTPSession.class);
        lenient().when(session.getMethod()).thenReturn(method);
        lenient().when(session.getUri()).thenReturn(uri);
        lenient().when(session.getQueryParameterString()).thenReturn(query);
        ProxyRequestStubs.stubBody(session, headers, requestBody);
        return session;
    }

    private String pathFromConfiguredEndpoint() {
        String endpoint = scannerSession.resolvedEndpoint();
        if (endpoint == null) {
            return "/";
        }
        return java.net.URI.create(endpoint).getRawPath();
    }

    private String queryFromConfiguredEndpoint() {
        String endpoint = scannerSession.resolvedEndpoint();
        if (endpoint == null) {
            return "";
        }
        String rawQuery = java.net.URI.create(endpoint).getRawQuery();
        // NanoHTTPD's HTTPSession.getQueryParameterString() never returns null — a request with no
        // query yields the empty string. Mirror that here so the mock is faithful to the runtime.
        return rawQuery != null ? rawQuery : "";
    }

    @Test
    @SuppressWarnings("unchecked")
    void serveStreamableHttp_doesNotRetryOnNon404Errors() throws Exception {
        String errorBody = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}";

        HttpResponse<InputStream> errorResponse = mockStreamResponse(500, "application/json", errorBody);
        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(errorResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        stubLegacyHttpServer(httpClient, errorResponse);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockAnonymousHttpSession("{}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(500);
            assertThat(new String(response.getData().readAllBytes())).isEqualTo(errorBody);
            verify(httpClient, times(4)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void serveStreamableHttp_rewritesJsonRpcIdWithUniqueSessionScopedValue() throws Exception {
        String originalBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}";
        String successBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";

        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> mockStreamResponse(200, "application/json", successBody));
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.nextRequestId()).thenReturn(7L, 8L, 9L);

        stubLegacyHttpServer(httpClient, mockStreamResponse(200, "application/json", successBody));

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        proxy.start();
        try {
            proxy.serve(mockAnonymousHttpSession(originalBody));
            proxy.serve(mockAnonymousHttpSession(originalBody));
            proxy.serve(mockAnonymousHttpSession(originalBody));

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(12)).send(captor.capture(), any(HttpResponse.BodyHandler.class));

            List<String> forwardedBodies = captor.getAllValues().stream()
                    .map(SseProxyServerTest::extractBody)
                    .filter(body -> body.contains("\"method\":\"tools/call\""))
                    .toList();

            assertThat(forwardedBodies.get(0)).contains("\"id\":7").doesNotContain("\"id\":1");
            assertThat(forwardedBodies.get(1)).contains("\"id\":8").doesNotContain("\"id\":1");
            assertThat(forwardedBodies.get(2)).contains("\"id\":9").doesNotContain("\"id\":1");
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void serveStreamableHttp_reinitializesAndRetriesOnceOn404WithoutJsonRpcErrorCode() throws Exception {
        String genericNotFoundBody = "Not Found";

        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        stubLegacyHttpServer(httpClient,
                () -> mockStreamResponse(404, "text/plain", genericNotFoundBody));

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockAnonymousHttpSession("{}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(404);
            assertThat(new String(response.getData().readAllBytes())).isEqualTo(genericNotFoundBody);
            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(7)).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            List<HttpRequest> requests = captor.getAllValues();
            assertThat(requests.stream().map(HttpRequest::method).toList())
                    .containsExactly("POST", "POST", "POST", "POST", "POST", "POST", "DELETE");
            assertThat(extractBody(requests.get(0))).contains("\"method\":\"initialize\"");
            assertThat(extractBody(requests.get(3))).contains("\"method\":\"initialize\"");
            assertThat(extractBody(requests.get(2))).isEqualTo("{}");
            assertThat(extractBody(requests.get(5))).isEqualTo("{}");
            assertIsolatedSessionCleanup(requests.get(6));
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void serve_preservesNotificationBodiesWithNoId() throws Exception {
        String notificationBody = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";
        String successBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";

        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> mockStreamResponse(200, "application/json", successBody));
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        stubLegacyHttpServer(httpClient, mockStreamResponse(200, "application/json", successBody));

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        proxy.start();
        try {
            proxy.serve(mockAnonymousHttpSession(notificationBody));

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(4)).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertIsolatedSessionCleanup(captor.getAllValues().get(3));

            assertThat(extractBody(captor.getAllValues().get(2))).isEqualTo(notificationBody);
            verify(scannerSession, never()).nextRequestId();
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void serve_handlesMalformedJsonBodyGracefully() throws Exception {
        String malformedBody = "not valid json";
        String successBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";

        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> mockStreamResponse(200, "application/json", successBody));
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        stubLegacyHttpServer(httpClient, mockStreamResponse(200, "application/json", successBody));

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockAnonymousHttpSession(malformedBody));

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(4)).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertIsolatedSessionCleanup(captor.getAllValues().get(3));
            assertThat(extractBody(captor.getAllValues().get(2))).isEqualTo(malformedBody);
            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            verify(logging, never()).logToError(anyString());
        } finally {
            proxy.stop();
        }
    }

    static String extractBody(HttpRequest request) {
        return request.bodyPublisher()
                .map(publisher -> {
                    BodyCollector collector = new BodyCollector();
                    publisher.subscribe(collector);
                    return collector.body();
                })
                .orElse("");
    }

    private static final class BodyCollector implements java.util.concurrent.Flow.Subscriber<java.nio.ByteBuffer> {
        private final java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
        @Override public void onSubscribe(java.util.concurrent.Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
        @Override public void onNext(java.nio.ByteBuffer item) {
            byte[] chunk = new byte[item.remaining()];
            item.get(chunk);
            buffer.writeBytes(chunk);
        }
        @Override public void onError(Throwable throwable) {}
        @Override public void onComplete() {}
        String body() { return buffer.toString(java.nio.charset.StandardCharsets.UTF_8); }
    }

    @Test
    @SuppressWarnings("unchecked")
    void repeaterSseOperationRecreatesSessionWithRefreshedBearer() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/message");
        when(scannerSession.sseUrl()).thenReturn("http://upstream/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        AtomicLong ids = new AtomicLong(42);
        when(scannerSession.nextRequestId()).thenAnswer(invocation -> ids.getAndIncrement());
        AtomicReference<String> token = new AtomicReference<>("Bearer old-token");
        when(scannerSession.scannerHeaders()).thenAnswer(invocation -> Map.of("Authorization", token.get()));
        when(scannerSession.beginAuthOperation()).thenReturn(response -> {
            token.set("Bearer refreshed-token");
            return com.mcpscanner.core.connection.RecoveryResult.RETRY;
        });
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if (request.method().equals("GET")) {
                        String events = "event: endpoint\ndata: /message\n\n"
                                + "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":" + ids.get()
                                + ",\"result\":{}}\n\n"
                                + "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{}}\n\n";
                        return mockStreamResponse(200, "text/event-stream", events);
                    }
                    boolean expiredOperation = extractBody(request).contains("tools/call")
                            && request.headers().firstValue("Authorization").orElse("").equals("Bearer old-token");
                    HttpResponse<String> response = mock(HttpResponse.class);
                    when(response.statusCode()).thenReturn(expiredOperation ? 401 : 202);
                    when(response.body()).thenReturn("");
                    if (expiredOperation) when(response.headers()).thenReturn(HttpHeaders.of(Map.of(), (a, b) -> true));
                    return response;
                });

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        try {
            NanoHTTPD.Response response = proxy.serve(mockManagedSession(proxy,
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            ArgumentCaptor<HttpRequest> requests = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(8)).send(requests.capture(), any());
            List<HttpRequest> operations = requests.getAllValues().stream()
                    .filter(request -> extractBody(request).contains("tools/call"))
                    .toList();
            assertThat(operations).hasSize(2);
            assertThat(operations.get(0).headers().firstValue("Authorization")).contains("Bearer old-token");
            assertThat(operations.get(1).headers().firstValue("Authorization")).contains("Bearer refreshed-token");
            assertThat(requests.getAllValues().stream().filter(request -> request.method().equals("GET"))
                    .map(request -> request.headers().firstValue("Authorization").orElse("")))
                    .containsExactly("Bearer old-token", "Bearer refreshed-token");
            verify(scannerSession).beginAuthOperation();
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void serveSse_retriesOnceOn401AfterAuthRefreshAndRebuildsSession() throws Exception {
        SseScanSession firstSession = mock(SseScanSession.class);
        SseScanSession secondSession = mock(SseScanSession.class);
        HttpClient httpClient = mock(HttpClient.class);
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient)
                .managedSessions(firstSession, secondSession).build();

        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.nextRequestId()).thenReturn(42L);
        when(scannerSession.beginAuthOperation()).thenReturn(response -> com.mcpscanner.core.connection.RecoveryResult.RETRY);

        ProxyResponse unauthorized = new ProxyResponse(401, "application/json", "{\"error\":\"invalid_token\"}");
        ProxyResponse success = new ProxyResponse(200, "application/json", "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        when(firstSession.forwardRequest(anyString(), anyMap())).thenReturn(unauthorized);
        when(secondSession.forwardRequest(anyString(), anyMap())).thenReturn(success);

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockManagedSession(proxy, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            verify(scannerSession, times(1)).beginAuthOperation();
            verify(firstSession, times(1)).forwardRequest(anyString(), anyMap());
            verify(firstSession, times(1)).close();
            verify(secondSession, times(1)).forwardRequest(anyString(), anyMap());
            ArgumentCaptor<String> outputMessage = ArgumentCaptor.forClass(String.class);
            verify(logging).logToOutput(outputMessage.capture());
            assertThat(outputMessage.getValue()).doesNotContain("OAuth");
            assertThat(eventLog.snapshot())
                    .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                            && entry.message().contains("Authentication recovery after 401, retrying"));
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void serveSse_doesNotRetryOn401WhenAuthRefreshFails() throws Exception {
        SseScanSession sseScanSession = mock(SseScanSession.class);
        HttpClient httpClient = mock(HttpClient.class);
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).managedSessions(sseScanSession).build();

        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.nextRequestId()).thenReturn(42L);
        when(scannerSession.beginAuthOperation()).thenReturn(response -> com.mcpscanner.core.connection.RecoveryResult.STOP);

        ProxyResponse unauthorized = new ProxyResponse(401, "application/json", "{\"error\":\"invalid_token\"}");
        when(sseScanSession.forwardRequest(anyString(), anyMap())).thenReturn(unauthorized);

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockManagedSession(proxy, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(401);
            verify(scannerSession, times(1)).beginAuthOperation();
            verify(sseScanSession, times(1)).forwardRequest(anyString(), anyMap());
            ArgumentCaptor<String> errorMessage = ArgumentCaptor.forClass(String.class);
            verify(logging).logToError(errorMessage.capture());
            assertThat(errorMessage.getValue()).doesNotContain("OAuth").startsWith("Authentication recovery stopped");
        } finally {
            proxy.stop();
        }
    }

    @Test
    void rejectsNonPostBeforeParsingBody() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}", NanoHTTPD.Method.GET, "/mcp", null);

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(405);
            verify(session, never()).parseBody(any());
            verifyNoInteractions(httpClient);
        } finally {
            proxy.stop();
        }
    }

    @Test
    void rejectsUnexpectedPathBeforeForwarding() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}", NanoHTTPD.Method.POST, "/admin", null);

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(404);
            verify(session, never()).parseBody(any());
            verifyNoInteractions(httpClient);
        } finally {
            proxy.stop();
        }
    }

    @Test
    void refusesBrowserRequestWithoutRoutingKeyBeforeForwarding() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}", NanoHTTPD.Method.POST, "/mcp", null,
                Map.of("origin", "http://rebound.example", "sec-fetch-site", "same-origin"));

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(403);
            verify(session, never()).getInputStream();
            verifyNoInteractions(httpClient);
            assertThat(eventLog.snapshot())
                    .filteredOn(entry -> entry.level() == McpEventLog.Level.WARN
                            && entry.message().contains("browser request refused"))
                    .hasSize(1);
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardsBrowserRequestCarryingTheRoutingKeyWithoutSendingTheKeyUpstream() throws Exception {
        String successBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json", successBody);
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        stubLegacyHttpServer(httpClient, upstreamResponse);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockAnonymousHttpSession(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}",
                Map.of("origin", "http://browser.example",
                        ScannerSentinels.ROUTED_HEADER.toLowerCase(), proxy.routingKey().value()));

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, atLeastOnce()).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertThat(captor.getAllValues())
                    .allSatisfy(sent -> assertThat(sent.headers().firstValue(ScannerSentinels.ROUTED_HEADER))
                            .isEmpty());
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void acceptsExpectedEndpointPathFromRewrittenBurpRequest() throws Exception {
        String successBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json", successBody);
        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/messages?session_id=abc");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        stubLegacyHttpServer(httpClient, upstreamResponse);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockAnonymousHttpSession(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}",
                NanoHTTPD.Method.POST, "/messages", "session_id=abc");

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            assertThat(new String(response.getData().readAllBytes())).isEqualTo(successBody);
            verify(session).getInputStream();
        } finally {
            proxy.stop();
        }
    }

    /**
     * Root-path regression: when the configured endpoint has no explicit path (e.g.
     * {@code https://mcp.example.com}), {@link java.net.URI#getRawPath()} returns the empty string
     * but the rewritten Burp request arrives with URI {@code "/"}. Without empty-path normalization
     * the proxy 404s the request even when the upstream really is at the root.
     */
    @Test
    @SuppressWarnings("unchecked")
    void isExpectedEndpointAcceptsRootPathRequest() throws Exception {
        String successBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json", successBody);
        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("https://mcp.example.com");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        stubLegacyHttpServer(httpClient, upstreamResponse);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockAnonymousHttpSession(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}",
                NanoHTTPD.Method.POST, "/", null);

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            assertThat(new String(response.getData().readAllBytes())).isEqualTo(successBody);
            verify(session).getInputStream();
        } finally {
            proxy.stop();
        }
    }

    /**
     * Streamable-HTTP regression: NanoHTTPD's {@code getQueryParameterString()} returns the empty
     * string (never {@code null}) for a request with no query, while {@link java.net.URI#getRawQuery()}
     * of a no-query endpoint is {@code null}. A query comparison would make {@code Objects.equals(null,
     * "")} false and 404 every {@code POST /mcp}. The proxy routes on path only (matching the
     * handler's path-only routing contract), so a no-query request to the no-query endpoint is
     * accepted.
     */
    @Test
    @SuppressWarnings("unchecked")
    void acceptsNoQueryStreamableHttpRequestToNoQueryEndpoint() throws Exception {
        String successBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json", successBody);
        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://127.0.0.1:8000/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        stubLegacyHttpServer(httpClient, upstreamResponse);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockAnonymousHttpSession(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}",
                NanoHTTPD.Method.POST, "/mcp", "");

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            assertThat(new String(response.getData().readAllBytes())).isEqualTo(successBody);
            verify(session).getInputStream();
        } finally {
            proxy.stop();
        }
    }

    /**
     * Path-only routing: a fuzzed/varying query (e.g. {@code /mcp?x=1}) against the {@code /mcp}
     * endpoint still routes — the path is what gates the match, never the query.
     */
    @Test
    @SuppressWarnings("unchecked")
    void acceptsFuzzedQueryRequestWhenPathMatches() throws Exception {
        String successBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json", successBody);
        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://127.0.0.1:8000/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        stubLegacyHttpServer(httpClient, upstreamResponse);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockAnonymousHttpSession(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}",
                NanoHTTPD.Method.POST, "/mcp", "x=1");

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            verify(session).getInputStream();
        } finally {
            proxy.stop();
        }
    }

    /**
     * Path-only routing: an SSE {@code /messages} endpoint with a configured {@code session_id}
     * query still routes a request whose query differs (fuzzed/standard requests vary the
     * {@code session_id}). The path gates the match; the query is ignored.
     */
    @Test
    @SuppressWarnings("unchecked")
    void acceptsVaryingQueryWhenPathMatchesConfiguredEndpointWithQuery() throws Exception {
        String successBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json", successBody);
        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/messages?session_id=abc");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        stubLegacyHttpServer(httpClient, upstreamResponse);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockAnonymousHttpSession("{}", NanoHTTPD.Method.POST, "/messages",
                "session_id=other");

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            verify(session).getInputStream();
        } finally {
            proxy.stop();
        }
    }

    @Test
    void rejectsDifferentPathBeforeForwarding() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/messages");

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}", NanoHTTPD.Method.POST, "/other",
                "session_id=abc");

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(404);
            verify(session, never()).parseBody(any());
            verifyNoInteractions(httpClient);
        } finally {
            proxy.stop();
        }
    }

    @Test
    void rejectsRequestWithWarnLogWhenConfiguredEndpointIsMalformed() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn(":::bad");

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}", NanoHTTPD.Method.POST, "/mcp", null);

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(404);
            verify(session, never()).parseBody(any());
            verifyNoInteractions(httpClient);
            assertThat(eventLog.snapshot())
                    .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                            && entry.message().contains("extension misconfiguration")
                            && entry.message().contains(":::bad"));
        } finally {
            proxy.stop();
        }
    }

    @Test
    void startsOnLoopbackInterfaceOnly() throws Exception {
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).build();
        proxy.start();
        try {
            String hostname = proxy.getHostname();
            assertThat(hostname).isEqualTo("127.0.0.1");
        } finally {
            proxy.stop();
        }
    }

    @Test
    void realLoopbackSocketGetReceives405WithoutParsingBody() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        proxy.start();
        try {
            String rawResponse = sendRawHttp(proxy.port(),
                    "GET /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");

            assertThat(rawResponse).startsWith("HTTP/1.1 405");
            verifyNoInteractions(httpClient);
        } finally {
            proxy.stop();
        }
    }

    @Test
    void realLoopbackSocketUnknownPathReceives404WithoutForwarding() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        proxy.start();
        try {
            String rawResponse = sendRawHttp(proxy.port(),
                    "POST /something-else HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}");

            assertThat(rawResponse).startsWith("HTTP/1.1 404");
            verifyNoInteractions(httpClient);
        } finally {
            proxy.stop();
        }
    }

    @Test
    void realLoopbackSocketRejectsLengthFreePost() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).postBodyLimit(2L).build();
        proxy.start();
        try (Socket socket = new Socket("127.0.0.1", proxy.port())) {
            socket.setSoTimeout(3000);
            socket.getOutputStream().write(("POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    + "Connection: close\r\n\r\n{}x").getBytes(StandardCharsets.UTF_8));
            socket.getOutputStream().flush();
            socket.shutdownOutput();

            String response = new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            assertThat(response).startsWith("HTTP/1.1 411");
            verifyNoInteractions(httpClient);
        } finally {
            proxy.stop();
        }
    }

    @Test
    void boundedProxyRejectsLengthFreePersistentPostPromptly() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).postBodyLimit(1024L).build();
        proxy.start();
        try (Socket socket = new Socket("127.0.0.1", proxy.port())) {
            socket.setSoTimeout(1500);
            socket.getOutputStream().write(("POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                    + "Connection: keep-alive\r\n\r\n{}").getBytes(StandardCharsets.UTF_8));
            socket.getOutputStream().flush();

            String status = new java.io.BufferedReader(new java.io.InputStreamReader(
                    socket.getInputStream(), StandardCharsets.UTF_8)).readLine();
            assertThat(status).startsWith("HTTP/1.1 411");
            verifyNoInteractions(httpClient);
        } finally {
            proxy.stop();
        }
    }

    private static String sendRawHttp(int port, String request) throws Exception {
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.getOutputStream().write(request.getBytes(StandardCharsets.UTF_8));
            socket.getOutputStream().flush();
            return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private void assertIsolatedSessionCleanup(HttpRequest request) {
        assertThat(request.method()).isEqualTo("DELETE");
        assertThat(request.headers().firstValue("Mcp-Session-Id")).contains("isolated-session");
    }

    @SuppressWarnings("unchecked")
    private void stubLegacyHttpServer(HttpClient httpClient, HttpResponse<InputStream> operationResponse)
            throws Exception {
        stubLegacyHttpServer(httpClient, () -> operationResponse);
    }

    @SuppressWarnings("unchecked")
    private void stubLegacyHttpServer(HttpClient httpClient,
                                      java.util.function.Supplier<HttpResponse<InputStream>> operationResponse)
            throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if (request.method().equals("DELETE")) {
                        return mockStreamResponse(204, "application/json", "");
                    }
                    com.fasterxml.jackson.databind.JsonNode envelope;
                    try {
                        envelope = com.mcpscanner.mcp.McpObjectMapper.INSTANCE.readTree(extractBody(request));
                    } catch (IOException malformedRequest) {
                        return operationResponse.get();
                    }
                    String method = envelope.path("method").asText();
                    if (method.equals("initialize")) {
                        String body = "{\"jsonrpc\":\"2.0\",\"id\":" + envelope.path("id")
                                + ",\"result\":{\"protocolVersion\":\"2025-03-26\","
                                + "\"capabilities\":{},\"serverInfo\":{\"name\":\"fixture\",\"version\":\"1\"}}}";
                        HttpResponse<InputStream> response = mockStreamResponse(200, "application/json", body);
                        lenient().when(response.headers().map()).thenReturn(Map.of(
                                "Mcp-Session-Id", List.of("isolated-session"),
                                "Content-Type", List.of("application/json")));
                        return response;
                    }
                    if (method.equals("notifications/initialized")) {
                        return mockStreamResponse(202, "application/json", "");
                    }
                    return operationResponse.get();
                });
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardStreamableHttp_omitsAuthorizationWhenStripSentinelPresent() throws Exception {
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        stubLegacyHttpServer(httpClient, upstreamResponse);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockAnonymousHttpSession("{}",
                Map.of("X-Mcp-Scanner-Strip-Auth", "1"));

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(4)).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertIsolatedSessionCleanup(captor.getAllValues().get(3));
            assertThat(captor.getAllValues().get(2).headers().firstValue("Authorization"))
                    .as("strip sentinel must suppress session Authorization injection")
                    .isEmpty();
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardStreamableHttp_omitsCookieAndCustomAuthWhenStripSentinelPresent() throws Exception {
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        stubLegacyHttpServer(httpClient, upstreamResponse);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockAnonymousHttpSession("{}",
                Map.of("X-Mcp-Scanner-Strip-Auth", "1"));

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(4)).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertIsolatedSessionCleanup(captor.getAllValues().get(3));
            HttpRequest outbound = captor.getAllValues().get(2);
            assertThat(outbound.headers().firstValue("Cookie")).isEmpty();
            assertThat(outbound.headers().firstValue("X-Api-Key")).isEmpty();
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardStreamableHttp_stripSentinelIsNeverForwardedUpstream() throws Exception {
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        stubLegacyHttpServer(httpClient, upstreamResponse);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockAnonymousHttpSession("{}",
                Map.of("X-Mcp-Scanner-Strip-Auth", "1"));

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(4)).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertIsolatedSessionCleanup(captor.getAllValues().get(3));
            assertThat(captor.getAllValues().get(2).headers().firstValue("X-Mcp-Scanner-Strip-Auth"))
                    .as("sentinel header must not leak to upstream MCP server")
                    .isEmpty();
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardStreamableHttp_forwardsAnUnknownCallerSessionIdUnchanged() throws Exception {
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        HttpClient httpClient = mock(HttpClient.class);
        stubLegacyHttpServer(httpClient, upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        when(scannerSession.protocolHeaders()).thenReturn(Map.of("Mcp-Session-Id", "session-stored"));

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockAnonymousHttpSession("{}",
                Map.of("Mcp-Session-Id", "session-from-scanner"));

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, atLeastOnce()).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            HttpRequest operation = captor.getAllValues().get(captor.getAllValues().size() - 1);
            assertThat(operation.headers().firstValue("Mcp-Session-Id"))
                    .contains("session-from-scanner");
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void anonymousHttpDoesNotReadAuthBearingSessionHeaders() throws Exception {
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockAnonymousHttpSession("{}",
                Map.of("X-Mcp-Scanner-Strip-Auth", "1"));

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            verify(scannerSession, never()).scannerHeaders();
            assertThat(captor.getValue().headers().firstValue("X-Future-Tracing")).isEmpty();
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardStreamableHttp_dropsKeepAliveHeaderForbiddenByHttpClientBuilder() throws Exception {
        // Java HttpRequest.Builder throws IllegalArgumentException for keep-alive/te/trailers
        // (see jdk.internal.net.http.common.Utils.DISALLOWED_HEADERS_SET). If a Burp config
        // forwarded one of these, the proxy would 502 — drop them at the proxy boundary.
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        stubLegacyHttpServer(httpClient, upstreamResponse);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockAnonymousHttpSession("{}", Map.of(
                "keep-alive", "timeout=5",
                "X-Custom", "keep-me"));

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(4)).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertIsolatedSessionCleanup(captor.getAllValues().get(3));
            HttpRequest outbound = captor.getAllValues().get(2);
            assertThat(outbound.headers().firstValue("X-Custom")).contains("keep-me");
            assertThat(outbound.headers().firstValue("Keep-Alive")).isEmpty();
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardStreamableHttp_filtersReservedTransportHeadersHostContentLengthConnection() throws Exception {
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        stubLegacyHttpServer(httpClient, upstreamResponse);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockAnonymousHttpSession("{}", Map.of(
                "host", "fuzz.target.example",
                "content-length", "2",
                "connection", "keep-alive",
                "X-Custom", "keep-me"));

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(4)).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertIsolatedSessionCleanup(captor.getAllValues().get(3));
            HttpRequest outbound = captor.getAllValues().get(2);
            // Java HttpClient's HttpRequest builder forbids Host/Content-Length/Connection — if
            // the proxy attempted to set them the build would throw IllegalArgumentException and
            // no request would be sent.
            assertThat(outbound.headers().firstValue("X-Custom")).contains("keep-me");
            assertThat(outbound.headers().firstValue("Host")).isEmpty();
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardStreamableHttp_setsWallClockTimeoutOnOutboundRequest() throws Exception {
        // A hostile/slow MCP server that answers with a never-ending text/event-stream (or just
        // stalls) must not tie up a proxy thread indefinitely. The shared HttpClient only sets a
        // connectTimeout, so the outbound request itself must carry a request timeout.
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        proxy.start();
        try {
            proxy.serve(mockAnonymousHttpSession("{}"));

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertThat(captor.getValue().timeout())
                    .as("outbound request must carry a wall-clock timeout so a stalling upstream "
                            + "cannot hang the proxy thread")
                    .isPresent();
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardStreamableHttp_mapsRequestTimeoutToBoundedErrorResponse() throws Exception {
        // When the request timeout expires the JDK client throws HttpTimeoutException; the proxy
        // must hand Burp a bounded error response rather than letting the exception escape.
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new java.net.http.HttpTimeoutException("request timed out"));
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockAnonymousHttpSession("{}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(502);
            assertThat(eventLog.snapshot())
                    .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                            && entry.message().contains("Proxy error"));
        } finally {
            proxy.stop();
        }
    }

    @Test
    void concurrencyLimiterIsConstructedWithExpectedCap() {
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(mock(HttpClient.class)).build();

        assertThat(proxy.concurrencyPermitsAvailable()).isEqualTo(32);
    }

    @Test
    void proxyResponseIsTopLevelType() {
        // Compile-time check: the top-level type lives in com.mcpscanner.proxy and is the
        // type SseScanSession.forwardRequest returns.
        com.mcpscanner.proxy.ProxyResponse response = new com.mcpscanner.proxy.ProxyResponse(200, "application/json", "{}");

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(SseProxyServer.class.getDeclaredClasses())
                .extracting(Class::getSimpleName)
                .doesNotContain("ProxyResponse");
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardStreamableHttp_doesNotDuplicateContentTypeOrAcceptWhenInboundRequestCarriesThem()
            throws Exception {
        // Regression: RESERVED_FORWARD_HEADERS was missing content-type and accept.
        // forwardStreamableHttp hardcodes both via builder.header(), then applyForwardHeaders
        // re-appended them from the inbound Burp request (which buildHeadersBlock always writes).
        // HttpRequest.Builder.header() appends, not replaces — strict servers received two
        // Content-Type headers and responded with HTTP 415. Assert allValues, not firstValue,
        // because firstValue() returns the first occurrence and masks the duplication.
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        HttpClient httpClient = mock(HttpClient.class);
        lenient().when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        stubLegacyHttpServer(httpClient, upstreamResponse);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockAnonymousHttpSession("{}", Map.of(
                "Content-Type", "application/json",
                "Accept", "application/json, text/event-stream"));

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(4)).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertIsolatedSessionCleanup(captor.getAllValues().get(3));
            HttpRequest outbound = captor.getAllValues().get(2);
            assertThat(outbound.headers().allValues("Content-Type"))
                    .as("Content-Type must appear exactly once — duplicate causes HTTP 415 on strict servers")
                    .containsExactly("application/json");
            assertThat(outbound.headers().allValues("Accept"))
                    .as("Accept must appear exactly once")
                    .hasSize(1);
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardStreamableHttp_dropsHopByHopAndProxyCredentialHeadersLikeTheSsePath() throws Exception {
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        stubLegacyHttpServer(httpClient, upstreamResponse);

        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        NanoHTTPD.IHTTPSession session = mockAnonymousHttpSession("{}", Map.of(
                "Proxy-Authorization", "Basic proxy-secret",
                "Via", "1.1 burp",
                "Trailer", "Expires",
                "X-Custom", "kept"));

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(4)).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            HttpRequest outbound = captor.getAllValues().get(2);
            assertThat(outbound.headers().firstValue("X-Custom")).contains("kept");
            for (String dropped : List.of("Proxy-Authorization", "Via", "Trailer")) {
                assertThat(outbound.headers().firstValue(dropped)).as(dropped).isEmpty();
            }
        } finally {
            proxy.stop();
        }
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<InputStream> mockStreamResponse(int statusCode, String contentType, String body) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        HttpHeaders headers = mock(HttpHeaders.class);
        lenient().when(headers.firstValue("Content-Type")).thenReturn(Optional.of(contentType));
        lenient().when(headers.allValues("Content-Type")).thenReturn(List.of(contentType));
        lenient().when(response.headers()).thenReturn(headers);
        lenient().when(response.statusCode()).thenReturn(statusCode);
        lenient().when(response.body()).thenReturn(new ByteArrayInputStream(body.getBytes()));
        return openedByAGet(response);
    }
}
