package com.mcpscanner.proxy;

import burp.api.montoya.logging.Logging;
import com.mcpscanner.logging.McpEventLog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

import static java.time.Duration.ofMillis;
import static java.time.Duration.ofSeconds;
import static org.awaitility.Awaitility.await;

import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SseScanSessionTest {

    @Mock private HttpClient httpClient;
    @Mock private Logging logging;

    private static final String SSE_URL = "http://localhost:3001/sse";
    private static final String ENDPOINT_EVENT = "event: endpoint\ndata: /message?sessionId=test-session\n\n";
    private static final long HANDSHAKE_ID = 100L;
    private static final String INITIALIZE_RESPONSE_EVENT =
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":" + HANDSHAKE_ID
                    + ",\"result\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"serverInfo\":{\"name\":\"t\",\"version\":\"0\"}}}\n\n";
    private static final String SSE_PRELUDE = ENDPOINT_EVENT + INITIALIZE_RESPONSE_EVENT;
    private static final String RESPONSE_JSON = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}";
    private static final String RESPONSE_EVENT = "event: message\ndata: " + RESPONSE_JSON + "\n\n";
    private static final String NOTIFICATION_EVENT = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n";
    private static final String REQUEST_BODY = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}";

    private static LongSupplier fixedHandshakeIdAllocator() {
        return () -> HANDSHAKE_ID;
    }

    private SseScanSession newSession(Map<String, String> authHeaders) {
        return new SseScanSession(SSE_URL, authHeaders, httpClient, fixedHandshakeIdAllocator(),
                new McpEventLog(null), logging);
    }

    private SseScanSession newSession(Map<String, String> authHeaders, Duration responseTimeout) {
        return new SseScanSession(SSE_URL, authHeaders, httpClient, fixedHandshakeIdAllocator(),
                responseTimeout, Duration.ofSeconds(5), new McpEventLog(null), logging);
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<InputStream> mockSseResponse(String sseContent) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        lenient().when(response.statusCode()).thenReturn(200);
        when(response.body()).thenReturn(new ByteArrayInputStream(sseContent.getBytes()));
        return response;
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<InputStream> mockSseResponse(InputStream body) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        lenient().when(response.statusCode()).thenReturn(200);
        when(response.body()).thenReturn(body);
        return response;
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<InputStream> mockSseResponseWithStatus(int statusCode, String sseContent) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        lenient().when(response.statusCode()).thenReturn(statusCode);
        when(response.body()).thenReturn(new ByteArrayInputStream(sseContent.getBytes()));
        return response;
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<String> mockPostResponse() {
        return mockPostResponse(202, "");
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<String> mockPostResponse(int statusCode, String body) {
        HttpResponse<String> response = mock(HttpResponse.class);
        lenient().when(response.statusCode()).thenReturn(statusCode);
        lenient().when(response.body()).thenReturn(body);
        return response;
    }

    @SuppressWarnings("unchecked")
    private void stubHttpClient(HttpResponse<InputStream> sseResponse, HttpResponse<String> postResponse)
            throws IOException, InterruptedException {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if ("GET".equals(request.method())) {
                        return sseResponse;
                    }
                    return postResponse;
                });
    }

    @Test
    void forwardRequestOpensSseConnectionAndReturnsResponse() throws Exception {
        String sseStream = SSE_PRELUDE + RESPONSE_EVENT;
        stubHttpClient(mockSseResponse(sseStream), mockPostResponse());

        try (SseScanSession session = newSession(Map.of())) {
            ProxyResponse result = session.forwardRequest(REQUEST_BODY, Map.of());

            assertThat(result.statusCode()).isEqualTo(200);
            assertThat(result.contentType()).isEqualTo("application/json");
            assertThat(result.body()).isEqualTo(RESPONSE_JSON);
        }
    }

    @Test
    void connectionEstablishedIsRoutedToBurpLogging() throws Exception {
        String sseStream = SSE_PRELUDE + RESPONSE_EVENT;
        stubHttpClient(mockSseResponse(sseStream), mockPostResponse());

        try (SseScanSession session = newSession(Map.of())) {
            session.forwardRequest(REQUEST_BODY, Map.of());

            verify(logging, atLeastOnce()).logToOutput(contains("SSE scan session connected"));
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardRequestReusesExistingConnection() throws Exception {
        QueueInputStream stream = new QueueInputStream();
        stream.push(SSE_PRELUDE);
        stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n");
        stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n");
        stubHttpClient(mockSseResponse(stream), mockPostResponse());

        String bodyA = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}";
        String bodyB = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{}}";

        try (SseScanSession session = newSession(Map.of())) {
            session.forwardRequest(bodyA, Map.of());
            session.forwardRequest(bodyB, Map.of());

            // 1 SSE GET + 2 handshake POSTs (initialize + notifications/initialized) + 2 scan POSTs.
            verify(httpClient, times(5)).send(any(), any());
        } finally {
            stream.close();
        }
    }

    @Test
    void forwardRequestSkipsNotificationsOnStream() throws Exception {
        String sseStream = SSE_PRELUDE + NOTIFICATION_EVENT + RESPONSE_EVENT;
        stubHttpClient(mockSseResponse(sseStream), mockPostResponse());

        try (SseScanSession session = newSession(Map.of())) {
            ProxyResponse result = session.forwardRequest(REQUEST_BODY, Map.of());

            assertThat(result.body()).isEqualTo(RESPONSE_JSON);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardRequestIncludesAuthHeaders() throws Exception {
        Map<String, String> authHeaders = Map.of("Authorization", "Bearer token123");
        String sseStream = SSE_PRELUDE + RESPONSE_EVENT;
        stubHttpClient(mockSseResponse(sseStream), mockPostResponse());

        try (SseScanSession session = newSession(authHeaders)) {
            session.forwardRequest(REQUEST_BODY, authHeaders);

            // GET (auth) + initialize POST (auth) + notifications/initialized POST (auth) + scan POST (auth) = 4
            verify(httpClient, times(4)).send(argThat(request ->
                    request.headers().firstValue("Authorization")
                            .map("Bearer token123"::equals).orElse(false)
            ), any());
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardRequestPostUsesPerRequestHeadersNotConnectTimeAuth() throws Exception {
        Map<String, String> connectTimeHeaders = Map.of("Authorization", "Bearer original");
        String sseStream = SSE_PRELUDE + RESPONSE_EVENT;
        stubHttpClient(mockSseResponse(sseStream), mockPostResponse());

        try (SseScanSession session = newSession(connectTimeHeaders)) {
            session.forwardRequest(REQUEST_BODY, Map.of());

            // The scan POST carries Burp's per-request headers (none here), so no Authorization.
            verify(httpClient).send(argThat(request ->
                    "POST".equals(request.method())
                            && request.headers().firstValue("Authorization").isEmpty()
            ), any());
            verify(httpClient).send(argThat(request ->
                    "GET".equals(request.method())
                            && request.headers().firstValue("Authorization")
                                    .map("Bearer original"::equals).orElse(false)
            ), any());
            // The two handshake POSTs use connect-time auth so the upstream MCP server accepts them.
            verify(httpClient, times(2)).send(argThat(request ->
                    "POST".equals(request.method())
                            && request.headers().firstValue("Authorization")
                                    .map("Bearer original"::equals).orElse(false)
            ), any());
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void postToMessageEndpoint_preservesScannerProvidedHeaders_doesNotInjectAuth() throws Exception {
        // Regression lock: SSE-transport scan POSTs must forward only scanner-provided headers
        // (Streamable-HTTP path now mirrors this — see SseProxyServerTest). If a future refactor
        // injects connect-time auth onto the scan POST it would mask every auth-bypass probe.
        Map<String, String> connectTimeAuth = Map.of(
                "Authorization", "Bearer session-token",
                "Cookie", "session=abc",
                "X-Api-Key", "secret");
        String sseStream = SSE_PRELUDE + RESPONSE_EVENT;
        stubHttpClient(mockSseResponse(sseStream), mockPostResponse());

        try (SseScanSession session = newSession(connectTimeAuth)) {
            Map<String, String> scannerHeaders = Map.of("X-Custom-Scanner", "probe-marker");
            session.forwardRequest(REQUEST_BODY, scannerHeaders);

            verify(httpClient).send(argThat(request ->
                    "POST".equals(request.method())
                            && request.uri().toString().contains("/message")
                            && request.headers().firstValue("X-Custom-Scanner")
                                    .map("probe-marker"::equals).orElse(false)
                            && request.headers().firstValue("Authorization").isEmpty()
                            && request.headers().firstValue("Cookie").isEmpty()
                            && request.headers().firstValue("X-Api-Key").isEmpty()
            ), any());
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void postToMessageEndpoint_doesNotForwardStripSentinelHeaderUpstream() throws Exception {
        // The strip-auth sentinel is a proxy-internal signal; it must never leak to the upstream
        // MCP server on the SSE message-endpoint POST.
        String sseStream = SSE_PRELUDE + RESPONSE_EVENT;
        stubHttpClient(mockSseResponse(sseStream), mockPostResponse());
        Map<String, String> scannerHeaders = Map.of(
                com.mcpscanner.mcp.ScannerSentinels.STRIP_AUTH_HEADER, "1",
                "X-Custom", "keep-me");

        try (SseScanSession session = newSession(Map.of())) {
            session.forwardRequest(REQUEST_BODY, scannerHeaders);

            verify(httpClient).send(argThat(request ->
                    "POST".equals(request.method())
                            && request.uri().toString().contains("/message")
                            && request.headers().firstValue("X-Custom")
                                    .map("keep-me"::equals).orElse(false)
                            && request.headers()
                                    .firstValue(com.mcpscanner.mcp.ScannerSentinels.STRIP_AUTH_HEADER)
                                    .isEmpty()
            ), any());
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void postToMessageEndpoint_dropsKeepAliveHeaderForbiddenByHttpClientBuilder() throws Exception {
        // Java HttpRequest.Builder throws IllegalArgumentException for keep-alive/te/trailers
        // (see jdk.internal.net.http.common.Utils.DISALLOWED_HEADERS_SET). If a Burp config
        // forwarded one of these to the SSE message-endpoint POST, the session would surface
        // as a 502 — drop them at the proxy boundary.
        String sseStream = SSE_PRELUDE + RESPONSE_EVENT;
        stubHttpClient(mockSseResponse(sseStream), mockPostResponse());
        Map<String, String> scannerHeaders = Map.of(
                "keep-alive", "timeout=5",
                "X-Custom", "keep-me");

        try (SseScanSession session = newSession(Map.of())) {
            ProxyResponse result = session.forwardRequest(REQUEST_BODY, scannerHeaders);

            assertThat(result.statusCode()).isEqualTo(200);
            verify(httpClient).send(argThat(request ->
                    "POST".equals(request.method())
                            && request.uri().toString().contains("/message")
                            && request.headers().firstValue("X-Custom")
                                    .map("keep-me"::equals).orElse(false)
                            && request.headers().firstValue("Keep-Alive").isEmpty()
            ), any());
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardRequestPostDropsReservedHopByHopHeaders() throws Exception {
        String sseStream = SSE_PRELUDE + RESPONSE_EVENT;
        stubHttpClient(mockSseResponse(sseStream), mockPostResponse());
        Map<String, String> burpHeaders = Map.of(
                "host", "fuzz.target.example",
                "content-length", "999",
                "X-Custom", "keep-me");

        try (SseScanSession session = newSession(Map.of())) {
            session.forwardRequest(REQUEST_BODY, burpHeaders);

            // Only the scan POST carries Burp-supplied headers; handshake POSTs use connect-time auth only.
            verify(httpClient).send(argThat(request ->
                    "POST".equals(request.method())
                            && request.headers().firstValue("X-Custom")
                                    .map("keep-me"::equals).orElse(false)
            ), any());
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardRequestReturnsErrorWhenStreamClosesWithoutResponse() throws Exception {
        // Stream completes the handshake then closes, so the scan waiter is failed by exitReader.
        String sseStream = SSE_PRELUDE;
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if ("GET".equals(request.method())) {
                        return mockSseResponse(sseStream);
                    }
                    return mockPostResponse();
                });

        try (SseScanSession session = newSession(Map.of())) {
            ProxyResponse result = session.forwardRequest(REQUEST_BODY, Map.of());

            assertThat(result.statusCode()).isEqualTo(502);
            assertThat(result.body()).contains("SSE stream closed");
        }
    }

    @Test
    void forwardRequestThrowsWhenEndpointNotDiscovered() throws Exception {
        String sseStream = "";
        stubHttpClient(mockSseResponse(sseStream), mockPostResponse());

        try (SseScanSession session = newSession(Map.of())) {
            assertThatThrownBy(() -> session.forwardRequest(REQUEST_BODY, Map.of()))
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("endpoint");
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardRequestReconnectsAfterStreamClosure() throws Exception {
        String firstStream = SSE_PRELUDE + RESPONSE_EVENT;
        String secondStream = SSE_PRELUDE + RESPONSE_EVENT;

        HttpResponse<String> postResponse = mockPostResponse();
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(new org.mockito.stubbing.Answer<Object>() {
                    private int getCount = 0;

                    @Override
                    public Object answer(org.mockito.invocation.InvocationOnMock invocation) {
                        HttpRequest request = invocation.getArgument(0);
                        if ("GET".equals(request.method())) {
                            getCount++;
                            return getCount == 1
                                    ? mockSseResponse(firstStream)
                                    : mockSseResponse(secondStream);
                        }
                        return postResponse;
                    }
                });

        try (SseScanSession session = newSession(Map.of())) {
            ProxyResponse result1 = session.forwardRequest(REQUEST_BODY, Map.of());
            assertThat(result1.statusCode()).isEqualTo(200);

            ProxyResponse result2 = session.forwardRequest(REQUEST_BODY, Map.of());
            assertThat(result2.statusCode()).isEqualTo(200);
            assertThat(result2.body()).isEqualTo(RESPONSE_JSON);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void closeClosesSseStream() throws Exception {
        String sseStream = SSE_PRELUDE + RESPONSE_EVENT;
        InputStream mockInputStream = spy(new ByteArrayInputStream(sseStream.getBytes()));
        HttpResponse<InputStream> sseResponse = mock(HttpResponse.class);
        when(sseResponse.body()).thenReturn(mockInputStream);

        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if ("GET".equals(request.method())) {
                        return sseResponse;
                    }
                    return mockPostResponse();
                });

        SseScanSession session = newSession(Map.of());
        session.forwardRequest(REQUEST_BODY, Map.of());
        session.close();

        verify(mockInputStream).close();
    }

    @Test
    void forwardRequest_doesNotSerializeConcurrentCalls() throws Exception {
        QueueInputStream stream = new QueueInputStream();
        stream.push(SSE_PRELUDE);
        stubHttpClient(mockSseResponse(stream), mockPostResponse());

        String bodyA = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}";
        String bodyB = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{}}";

        try (SseScanSession session = newSession(Map.of())) {
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                Future<ProxyResponse> futureA =
                        executor.submit(() -> session.forwardRequest(bodyA, Map.of()));
                Future<ProxyResponse> futureB =
                        executor.submit(() -> session.forwardRequest(bodyB, Map.of()));

                // Wait until both calls have dispatched their POSTs before pushing responses.
                await().atMost(ofSeconds(2)).until(() -> session.pendingRequests() >= 2);

                // Push request 2's response FIRST — it must complete before A.
                stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"ok\":true}}\n\n");

                ProxyResponse responseB = futureB.get(2, TimeUnit.SECONDS);
                assertThat(responseB.body()).contains("\"id\":2");
                assertThat(futureA.isDone()).isFalse();

                stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n");

                ProxyResponse responseA = futureA.get(2, TimeUnit.SECONDS);
                assertThat(responseA.body()).contains("\"id\":1");
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    void forwardRequest_timesOutGracefullyWhenServerNeverResponds() throws Exception {
        QueueInputStream stream = new QueueInputStream();
        // Handshake completes; scan POST is then awaited and must time out.
        stream.push(SSE_PRELUDE);
        stubHttpClient(mockSseResponse(stream), mockPostResponse());

        try (SseScanSession session = new SseScanSession(
                SSE_URL, Map.of(), httpClient, fixedHandshakeIdAllocator(),
                Duration.ofMillis(150), Duration.ofSeconds(5), new McpEventLog(null), logging)) {
            ProxyResponse result = session.forwardRequest(REQUEST_BODY, Map.of());

            assertThat(result.statusCode()).isEqualTo(502);
            assertThat(result.body()).contains("Timed out");
        } finally {
            stream.close();
        }
    }

    @Test
    void close_failsAllPendingWaiters() throws Exception {
        QueueInputStream stream = new QueueInputStream();
        // Pre-complete the handshake so both scan calls register waiters that close() can fail.
        stream.push(SSE_PRELUDE);
        stubHttpClient(mockSseResponse(stream), mockPostResponse());

        String bodyA = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}";
        String bodyB = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{}}";

        SseScanSession session = newSession(Map.of());
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<ProxyResponse> futureA =
                    executor.submit(() -> session.forwardRequest(bodyA, Map.of()));
            Future<ProxyResponse> futureB =
                    executor.submit(() -> session.forwardRequest(bodyB, Map.of()));

            await().atMost(ofSeconds(2)).until(() -> session.pendingRequests() >= 2);
            assertThat(session.pendingRequests()).isEqualTo(2);

            session.close();

            ProxyResponse responseA = futureA.get(1, TimeUnit.SECONDS);
            ProxyResponse responseB = futureB.get(1, TimeUnit.SECONDS);
            assertThat(responseA.statusCode()).isEqualTo(502);
            assertThat(responseA.body()).contains("Session closed");
            assertThat(responseB.statusCode()).isEqualTo(502);
            assertThat(responseB.body()).contains("Session closed");
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void forwardRequest_pendingResponseBufferIsBounded() throws Exception {
        QueueInputStream stream = new QueueInputStream();
        stream.push(SSE_PRELUDE);
        int overrun = SseScanSession.PENDING_RESPONSE_CAP + 10;
        for (int i = 1; i <= overrun; i++) {
            stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":" + i + ",\"result\":{}}\n\n");
        }
        String markerId = String.valueOf(overrun + 1);
        stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":" + markerId + ",\"result\":{}}\n\n");
        stubHttpClient(mockSseResponse(stream), mockPostResponse());

        try (SseScanSession session = newSession(Map.of())) {
            ProxyResponse response = session.forwardRequest(
                    "{\"jsonrpc\":\"2.0\",\"id\":" + markerId + ",\"method\":\"tools/call\",\"params\":{}}",
                    Map.of());

            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(session.pendingResponseCount()).isLessThanOrEqualTo(SseScanSession.PENDING_RESPONSE_CAP);
        } finally {
            stream.close();
        }
    }

    @Test
    void readerThreadRecoversFromMalformedEventsOnStream() throws Exception {
        QueueInputStream stream = new QueueInputStream();
        stream.push(SSE_PRELUDE);
        stream.push("event: message\ndata: not-json\n\n");
        stubHttpClient(mockSseResponse(stream), mockPostResponse());

        try (SseScanSession session = newSession(Map.of())) {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<ProxyResponse> future =
                        executor.submit(() -> session.forwardRequest(REQUEST_BODY, Map.of()));

                await().atMost(ofSeconds(2)).until(() -> session.pendingRequests() >= 1);
                stream.push(RESPONSE_EVENT);

                ProxyResponse result = future.get(2, TimeUnit.SECONDS);
                assertThat(result.statusCode()).isEqualTo(200);
                assertThat(result.body()).isEqualTo(RESPONSE_JSON);
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    void forwardRequest_doesNotDispatchServerInitiatedMessagesLackingMatchingWaiter() throws Exception {
        QueueInputStream stream = new QueueInputStream();
        stream.push(SSE_PRELUDE);
        stubHttpClient(mockSseResponse(stream), mockPostResponse());

        try (SseScanSession session = newSession(Map.of())) {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<ProxyResponse> future =
                        executor.submit(() -> session.forwardRequest(REQUEST_BODY, Map.of()));

                await().atMost(ofSeconds(2)).until(() -> session.pendingRequests() >= 1);
                stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n");
                stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":999,\"result\":{\"orphan\":true}}\n\n");

                // Confirm unmatched responses did not resolve the waiter.
                await().during(ofMillis(150)).atMost(ofMillis(500)).until(() -> !future.isDone());
                assertThat(future.isDone()).isFalse();

                stream.push(RESPONSE_EVENT);
                ProxyResponse result = future.get(2, TimeUnit.SECONDS);
                assertThat(result.body()).isEqualTo(RESPONSE_JSON);
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardRequest_completesInitializeHandshakeBeforeForwardingScanRequests() throws Exception {
        QueueInputStream stream = new QueueInputStream();
        stream.push(ENDPOINT_EVENT);
        stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"serverInfo\":{\"name\":\"test\",\"version\":\"0\"}}}\n\n");
        stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[]}}\n\n");
        stubHttpClient(mockSseResponse(stream), mockPostResponse());

        AtomicLong counter = new AtomicLong(1);
        LongSupplier idAllocator = counter::getAndIncrement;
        String scanBody = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{}}";

        try (SseScanSession session = new SseScanSession(SSE_URL, Map.of(), httpClient, idAllocator,
                new McpEventLog(null), logging)) {
            ProxyResponse result = session.forwardRequest(scanBody, Map.of());

            assertThat(result.statusCode()).isEqualTo(200);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, atLeast(4)).send(captor.capture(), any());

            List<HttpRequest> posts = captor.getAllValues().stream()
                    .filter(req -> "POST".equals(req.method()))
                    .toList();
            assertThat(posts).hasSize(3);

            List<String> bodies = posts.stream()
                    .map(SseProxyServerTest::extractBody)
                    .toList();
            assertThat(bodies.get(0))
                    .contains("\"method\":\"initialize\"")
                    .contains("\"id\":1");
            assertThat(bodies.get(1)).contains("\"method\":\"notifications/initialized\"");
            assertThat(bodies.get(2)).contains("\"method\":\"tools/call\"");
        } finally {
            stream.close();
        }
    }

    @Test
    void ensureConnected_propagatesInitializeFailureAndLeavesSessionDisconnected() throws Exception {
        // Stream provides the endpoint event but immediately closes, so the initialize
        // waiter is failed by the reader thread's exitReader path.
        String sseStream = ENDPOINT_EVENT;
        stubHttpClient(mockSseResponse(sseStream), mockPostResponse());

        try (SseScanSession session = newSession(Map.of())) {
            assertThatThrownBy(() -> session.forwardRequest(REQUEST_BODY, Map.of()))
                    .isInstanceOf(IOException.class);

            assertThat(session.pendingRequests()).isEqualTo(0);
        }
    }

    @Test
    void ensureConnected_timesOutWhenInitializeResponseNeverArrives() throws Exception {
        // Endpoint event is delivered, but no initialize response is ever pushed.
        QueueInputStream stream = new QueueInputStream();
        stream.push(ENDPOINT_EVENT);
        stubHttpClient(mockSseResponse(stream), mockPostResponse());

        try (SseScanSession session = new SseScanSession(
                SSE_URL, Map.of(), httpClient, fixedHandshakeIdAllocator(),
                Duration.ofSeconds(5), Duration.ofMillis(150), new McpEventLog(null), logging)) {
            long started = System.currentTimeMillis();
            assertThatThrownBy(() -> session.forwardRequest(REQUEST_BODY, Map.of()))
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("initialize");
            long elapsed = System.currentTimeMillis() - started;
            assertThat(elapsed).isLessThan(2_000);
        } finally {
            stream.close();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardRequest_doesNotRepeatHandshakeOnSecondCall() throws Exception {
        QueueInputStream stream = new QueueInputStream();
        stream.push(SSE_PRELUDE);
        stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n");
        stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n");
        stubHttpClient(mockSseResponse(stream), mockPostResponse());

        String bodyA = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}";
        String bodyB = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{}}";

        try (SseScanSession session = newSession(Map.of())) {
            session.forwardRequest(bodyA, Map.of());
            session.forwardRequest(bodyB, Map.of());

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, atLeast(1)).send(captor.capture(), any());

            List<String> handshakeBodies = captor.getAllValues().stream()
                    .filter(req -> "POST".equals(req.method()))
                    .map(SseProxyServerTest::extractBody)
                    .toList();
            long initializeCount = handshakeBodies.stream()
                    .filter(body -> body.contains("\"method\":\"initialize\""))
                    .count();
            long initializedCount = handshakeBodies.stream()
                    .filter(body -> body.contains("\"method\":\"notifications/initialized\""))
                    .count();

            assertThat(initializeCount).isEqualTo(1);
            assertThat(initializedCount).isEqualTo(1);
        } finally {
            stream.close();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardRequest_propagates401StatusFromMessageEndpoint() throws Exception {
        QueueInputStream stream = new QueueInputStream();
        stream.push(SSE_PRELUDE);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if ("GET".equals(request.method())) {
                        return mockSseResponse(stream);
                    }
                    String body = SseProxyServerTest.extractBody(request);
                    if (body.contains("\"method\":\"initialize\"") || body.contains("\"method\":\"notifications/initialized\"")) {
                        return mockPostResponse(202, "");
                    }
                    return mockPostResponse(401, "{\"error\":\"invalid_token\"}");
                });

        try (SseScanSession session = newSession(Map.of(), Duration.ofMillis(500))) {
            ProxyResponse result = session.forwardRequest(REQUEST_BODY, Map.of());

            assertThat(result.statusCode()).isEqualTo(401);
            assertThat(result.body()).contains("invalid_token");
            assertThat(session.pendingRequests()).isZero();
        } finally {
            stream.close();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardRequest_propagates500StatusAndBodyFromMessageEndpoint() throws Exception {
        QueueInputStream stream = new QueueInputStream();
        stream.push(SSE_PRELUDE);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if ("GET".equals(request.method())) {
                        return mockSseResponse(stream);
                    }
                    String body = SseProxyServerTest.extractBody(request);
                    if (body.contains("\"method\":\"initialize\"") || body.contains("\"method\":\"notifications/initialized\"")) {
                        return mockPostResponse(202, "");
                    }
                    return mockPostResponse(500, "upstream blew up");
                });

        try (SseScanSession session = newSession(Map.of(), Duration.ofMillis(500))) {
            ProxyResponse result = session.forwardRequest(REQUEST_BODY, Map.of());

            assertThat(result.statusCode()).isEqualTo(500);
            assertThat(result.body()).isEqualTo("upstream blew up");
        } finally {
            stream.close();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardRequest_propagates401StatusFromSseStreamOpen() throws Exception {
        HttpResponse<InputStream> unauthorizedStream =
                mockSseResponseWithStatus(401, "{\"error\":\"invalid_token\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(unauthorizedStream);

        try (SseScanSession session = newSession(Map.of())) {
            ProxyResponse result = session.forwardRequest(REQUEST_BODY, Map.of());

            assertThat(result.statusCode()).isEqualTo(401);
            assertThat(result.body()).contains("invalid_token");
            assertThat(session.pendingRequests()).isZero();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardRequest_propagates401WithoutInvokingMessagePost() throws Exception {
        HttpResponse<InputStream> unauthorizedStream =
                mockSseResponseWithStatus(401, "{\"error\":\"invalid_token\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(unauthorizedStream);

        try (SseScanSession session = newSession(Map.of())) {
            session.forwardRequest(REQUEST_BODY, Map.of());

            // Only the GET; no handshake POSTs should be issued when stream-open fails with 401.
            verify(httpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        }
    }

    @Test
    void disconnect_doesNotBlockConcurrentForwarders() throws Exception {
        // The SSE stream stays open (QueueInputStream never sends EOF) so the reader
        // thread blocks on the socket read after the stream is interrupted. This means
        // disconnect()'s join(1000) would block for up to 1 s — the fix must release
        // 'this' before that join so concurrent forwardRequest callers are not delayed.
        QueueInputStream stream = new QueueInputStream();
        stream.push(SSE_PRELUDE);
        stubHttpClient(mockSseResponse(stream), mockPostResponse());

        SseScanSession session = newSession(Map.of());
        // Establish the connection so 'connected=true'.
        ExecutorService connectors = Executors.newSingleThreadExecutor();
        try {
            // Warm up: get the session connected by sending a request that won't complete
            // (no response pushed yet) — we just need the handshake done. But forwardRequest
            // will block waiting for a response. Instead, drive connection via a separate body
            // with an id we'll never push, then let it time out.
            // Easier approach: push a response for the warm-up request.
            String warmBody = "{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"tools/call\",\"params\":{}}";
            stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":99,\"result\":{}}\n\n");
            session.forwardRequest(warmBody, Map.of());
        } finally {
            connectors.shutdown();
        }

        // Now the session is connected. Start a disconnect on a background thread.
        // The QueueInputStream reader is blocked in queue.take() — closing the stream
        // causes an IOException which exits the read loop. The join(1000) on the
        // reader thread waits for it, but under the fix this happens OUTSIDE the lock.
        CountDownLatch disconnectStarted = new CountDownLatch(1);
        CountDownLatch disconnectDone = new CountDownLatch(1);
        ExecutorService disconnector = Executors.newSingleThreadExecutor();
        try {
            disconnector.submit(() -> {
                disconnectStarted.countDown();
                try {
                    session.close();
                } catch (Exception ignored) {
                }
                disconnectDone.countDown();
            });

            // Wait until disconnect has started (so 'disconnecting' flag is set).
            assertThat(disconnectStarted.await(2, TimeUnit.SECONDS)).isTrue();

            // Give disconnect a moment to enter the synchronized block and set the flag.
            Thread.sleep(20);

            // A concurrent forwardRequest should return quickly (within 100 ms),
            // NOT block for up to 1 s waiting to acquire 'this'.
            long before = System.nanoTime();
            ProxyResponse result = session.forwardRequest(
                    "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{}}", Map.of());
            long elapsedMs = (System.nanoTime() - before) / 1_000_000;

            assertThat(result.statusCode()).isEqualTo(502);
            assertThat(result.body()).contains("Session closed");
            assertThat(elapsedMs).as("forwardRequest should return fast while disconnect holds join").isLessThan(100);

            assertThat(disconnectDone.await(3, TimeUnit.SECONDS)).isTrue();
        } finally {
            disconnector.shutdownNow();
            stream.close();
        }
    }

    @Test
    void forwardRequest_returnsTopLevelProxyResponseType() throws Exception {
        String sseStream = SSE_PRELUDE + RESPONSE_EVENT;
        stubHttpClient(mockSseResponse(sseStream), mockPostResponse());

        try (SseScanSession session = newSession(Map.of())) {
            // Compile-time check: forwardRequest returns com.mcpscanner.proxy.ProxyResponse (top-level).
            com.mcpscanner.proxy.ProxyResponse result = session.forwardRequest(REQUEST_BODY, Map.of());

            assertThat(result.statusCode()).isEqualTo(200);
        }
    }

    @Test
    void sseProxyServer_doesNotDeclareNestedProxyResponse() {
        Class<?>[] nested = SseProxyServer.class.getDeclaredClasses();

        assertThat(nested)
                .extracting(Class::getSimpleName)
                .doesNotContain("ProxyResponse");
    }

    /** InputStream backed by a BlockingQueue so tests can push SSE bytes on demand. */
    static final class QueueInputStream extends InputStream {
        private static final byte[] EOF = new byte[0];
        private final BlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
        private byte[] current = new byte[0];
        private int pos = 0;
        private volatile boolean closed = false;

        void push(String chunk) {
            queue.add(chunk.getBytes(StandardCharsets.UTF_8));
        }

        void finish() {
            queue.add(EOF);
        }

        @Override
        public int read() throws IOException {
            if (closed && pos >= current.length && queue.isEmpty()) {
                return -1;
            }
            while (pos >= current.length) {
                try {
                    current = queue.take();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException(e);
                }
                if (current == EOF) {
                    closed = true;
                    return -1;
                }
                pos = 0;
            }
            return current[pos++] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) {
                return 0;
            }
            int first = read();
            if (first == -1) {
                return -1;
            }
            b[off] = (byte) first;
            int written = 1;
            while (written < len && pos < current.length) {
                b[off + written++] = current[pos++];
            }
            return written;
        }

        @Override
        public int available() {
            return Math.max(0, current.length - pos);
        }

        @Override
        public void close() {
            closed = true;
            queue.offer(EOF);
        }
    }
}
