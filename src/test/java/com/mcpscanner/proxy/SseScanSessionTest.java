package com.mcpscanner.proxy;

import burp.api.montoya.logging.Logging;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.config.RedirectMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import com.mcpscanner.core.protocol.ClientInfo;
import com.mcpscanner.core.protocol.ClientProfile;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

import static com.mcpscanner.testutil.OpenedStreams.openedByAGet;
import static com.mcpscanner.testutil.AwaitedFutures.doneWithin;
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
        return TestSseSessions.builder(SSE_URL, httpClient).headers(authHeaders).requestIds(fixedHandshakeIdAllocator()).eventLog(new McpEventLog(logging)).build();
    }

    private SseScanSession newSession(Map<String, String> authHeaders,
                                      java.util.function.Supplier<RedirectMode> redirectMode) {
        return TestSseSessions.builder(SSE_URL, httpClient).headers(authHeaders).requestIds(fixedHandshakeIdAllocator())
                .redirectMode(redirectMode).eventLog(new McpEventLog(logging)).build();
    }

    private SseScanSession newSession(Map<String, String> authHeaders, Duration responseTimeout) {
        return TestSseSessions.builder(SSE_URL, httpClient).headers(authHeaders).requestIds(fixedHandshakeIdAllocator()).timeouts(responseTimeout, Duration.ofSeconds(5)).eventLog(new McpEventLog(logging)).build();
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<InputStream> mockSseResponse(String sseContent) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        lenient().when(response.statusCode()).thenReturn(200);
        when(response.body()).thenReturn(new ByteArrayInputStream(sseContent.getBytes()));
        return openedByAGet(response);
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<InputStream> mockSseResponse(InputStream body) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        lenient().when(response.statusCode()).thenReturn(200);
        when(response.body()).thenReturn(body);
        return openedByAGet(response);
    }

    @SuppressWarnings("unchecked")
    private HttpResponse<InputStream> mockSseResponseWithStatus(int statusCode, String sseContent) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        lenient().when(response.statusCode()).thenReturn(statusCode);
        when(response.headers()).thenReturn(java.net.http.HttpHeaders.of(Map.of(), (a, b) -> true));
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
        if (statusCode == 401 || statusCode == 403)
            when(response.headers()).thenReturn(java.net.http.HttpHeaders.of(Map.of(), (a, b) -> true));
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
    void operationPostRejectsOversizedBodyBeforeConsumingRemainderAndRecovers() throws Exception {
        QueueInputStream stream = new QueueInputStream();
        stream.push(SSE_PRELUDE);
        HttpResponse<InputStream> opened = mockSseResponse(stream);
        HttpResponse<String> accepted = mockPostResponse();
        java.util.concurrent.atomic.AtomicInteger consumed = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicBoolean cancelled = new java.util.concurrent.atomic.AtomicBoolean();
        java.util.concurrent.atomic.AtomicInteger operations = new java.util.concurrent.atomic.AtomicInteger();
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if (request.method().equals("GET")) return opened;
                    if (!SseProxyServerTest.extractBody(request).contains("tools/call")) return accepted;
                    if (operations.incrementAndGet() > 1) return mockPostResponse(409, "recovered");
                    return receivePostBody(invocation.getArgument(1),
                            com.mcpscanner.mcp.BoundedBodyReader.MAX_RESPONSE_BYTES * 2,
                            consumed, cancelled);
                });
        try (SseScanSession session = newSession(Map.of())) {
            assertThatThrownBy(() -> session.forwardRequest(REQUEST_BODY, Map.of()))
                    .isInstanceOf(IOException.class).hasMessageContaining("exceeded");
            assertThat(cancelled).isTrue();
            assertThat(consumed.get()).isLessThanOrEqualTo(
                    com.mcpscanner.mcp.BoundedBodyReader.MAX_RESPONSE_BYTES + 8192);
            assertThat(session.pendingRequests()).isZero();
            ProxyResponse recovered = session.forwardRequest(REQUEST_BODY, Map.of());
            assertThat(recovered.statusCode()).isEqualTo(409);
            assertThat(recovered.body()).isEqualTo("recovered");
        } finally {
            stream.close();
        }
    }

    @Test
    void operationPostAcceptsBodyAtExactByteLimitAndPreservesStatus() throws Exception {
        QueueInputStream stream = new QueueInputStream();
        stream.push(SSE_PRELUDE);
        HttpResponse<InputStream> opened = mockSseResponse(stream);
        HttpResponse<String> accepted = mockPostResponse();
        java.util.concurrent.atomic.AtomicInteger consumed = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicBoolean cancelled = new java.util.concurrent.atomic.AtomicBoolean();
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if (request.method().equals("GET")) return opened;
                    if (!SseProxyServerTest.extractBody(request).contains("tools/call")) return accepted;
                    return receivePostBody(invocation.getArgument(1),
                            com.mcpscanner.mcp.BoundedBodyReader.MAX_RESPONSE_BYTES, consumed, cancelled);
                });
        try (SseScanSession session = newSession(Map.of())) {
            ProxyResponse response = session.forwardRequest(REQUEST_BODY, Map.of());
            assertThat(response.statusCode()).isEqualTo(409);
            assertThat(response.body()).hasSize(com.mcpscanner.mcp.BoundedBodyReader.MAX_RESPONSE_BYTES)
                    .isEqualTo("x".repeat(com.mcpscanner.mcp.BoundedBodyReader.MAX_RESPONSE_BYTES));
            assertThat(cancelled).isFalse();
            assertThat(session.pendingRequests()).isZero();
        } finally {
            stream.close();
        }
    }

    private HttpResponse<String> receivePostBody(HttpResponse.BodyHandler<String> handler, int size,
            java.util.concurrent.atomic.AtomicInteger consumed,
            java.util.concurrent.atomic.AtomicBoolean cancelled) throws Exception {
        HttpResponse.BodySubscriber<String> subscriber = handler.apply(mock(HttpResponse.ResponseInfo.class));
        subscriber.onSubscribe(new java.util.concurrent.Flow.Subscription() {
            public void request(long count) { }
            public void cancel() { cancelled.set(true); }
        });
        while (consumed.get() < size && !cancelled.get()) {
            int length = Math.min(8192, size - consumed.get());
            byte[] chunk = new byte[length];
            java.util.Arrays.fill(chunk, (byte) 'x');
            consumed.addAndGet(length);
            subscriber.onNext(List.of(java.nio.ByteBuffer.wrap(chunk)));
        }
        if (!cancelled.get()) subscriber.onComplete();
        try {
            return mockPostResponse(409, subscriber.getBody().toCompletableFuture().get());
        } catch (java.util.concurrent.ExecutionException error) {
            throw new IOException(error.getCause().getMessage(), error.getCause());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void operationPostHeadersAndBodyHaveDeadline(boolean stalledBody) throws Exception {
        QueueInputStream stream = new QueueInputStream();
        stream.push(SSE_PRELUDE);
        java.util.concurrent.CompletableFuture<Void> releasePost = new java.util.concurrent.CompletableFuture<>();
        HttpResponse<InputStream> opened = mockSseResponse(stream);
        HttpResponse<String> accepted = mockPostResponse();
        HttpResponse<String> stalled = mockPostResponse();
        if (stalledBody) {
            when(stalled.body()).thenAnswer(invocation -> {
                releasePost.get();
                return "";
            });
        }
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if (request.method().equals("GET")) return opened;
                    String body = SseProxyServerTest.extractBody(request);
                    if (!body.contains("tools/call")) return accepted;
                    if (!stalledBody) releasePost.get();
                    return stalled;
                });
        SseScanSession session = newSession(Map.of(), ofMillis(150));
        java.util.concurrent.CompletableFuture<ProxyResponse> result =
                java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                    try {
                        return session.forwardRequest(REQUEST_BODY, Map.of());
                    } catch (Exception e) {
                        throw new java.util.concurrent.CompletionException(e);
                    }
                });
        try {
            assertThatThrownBy(doneWithin(result, ofSeconds(1))::get)
                    .isInstanceOf(java.util.concurrent.ExecutionException.class)
                    .hasCauseInstanceOf(IOException.class);
            assertThat(session.pendingRequests()).isZero();
        } finally {
            releasePost.complete(null);
            session.close();
            stream.close();
        }
    }

    @Test
    void responseHeadersMustArriveWithinHandshakeDeadline() throws Exception {
        java.util.concurrent.CompletableFuture<Void> releaseHeaders = new java.util.concurrent.CompletableFuture<>();
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    assertThat(request.timeout()).contains(ofMillis(150));
                    releaseHeaders.get();
                    throw new IOException("Headers released by cleanup");
                });
        SseScanSession session = TestSseSessions.builder(SSE_URL, httpClient).headers(Map.of()).requestIds(fixedHandshakeIdAllocator()).timeouts(ofSeconds(5), ofMillis(150)).eventLog(new McpEventLog(null)).build();
        java.util.concurrent.CompletableFuture<ProxyResponse> result =
                java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                    try {
                        return session.forwardRequest(REQUEST_BODY, Map.of());
                    } catch (Exception e) {
                        throw new java.util.concurrent.CompletionException(e);
                    }
                });
        try {
            assertThatThrownBy(doneWithin(result, ofSeconds(1))::get)
                    .isInstanceOf(java.util.concurrent.ExecutionException.class)
                    .hasCauseInstanceOf(IOException.class);
        } finally {
            releaseHeaders.complete(null);
            session.close();
        }
    }

    @Test
    void endpointEventMustArriveWithinHandshakeDeadline() throws Exception {
        QueueInputStream stream = new QueueInputStream();
        stubHttpClient(mockSseResponse(stream), mockPostResponse());
        SseScanSession session = TestSseSessions.builder(SSE_URL, httpClient).headers(Map.of()).requestIds(fixedHandshakeIdAllocator()).timeouts(ofSeconds(5), ofMillis(150)).eventLog(new McpEventLog(null)).build();
        java.util.concurrent.CompletableFuture<ProxyResponse> result =
                java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                    try {
                        return session.forwardRequest(REQUEST_BODY, Map.of());
                    } catch (Exception e) {
                        throw new java.util.concurrent.CompletionException(e);
                    }
                });
        try {
            assertThatThrownBy(doneWithin(result, ofSeconds(1))::get)
                    .isInstanceOf(java.util.concurrent.ExecutionException.class)
                    .hasCauseInstanceOf(IOException.class);
        } finally {
            stream.close();
            session.close();
        }
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
    void connectionLogRedactsTheSessionIdInTheMessageEndpoint() throws Exception {
        stubHttpClient(mockSseResponse(SSE_PRELUDE + RESPONSE_EVENT), mockPostResponse());

        try (SseScanSession session = newSession(Map.of())) {
            session.forwardRequest(REQUEST_BODY, Map.of());

            verify(logging, atLeastOnce()).logToOutput(contains("/message?<redacted>"));
            verify(logging, never()).logToOutput(contains("test-session"));
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
    void forwardRequestPostsIdLessNotificationAndReturnsTheServersNoReplyStatus() throws Exception {
        String notification = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\","
                + "\"params\":{\"progressToken\":\"p\",\"progress\":1}}";
        stubHttpClient(mockSseResponse(SSE_PRELUDE), mockPostResponse(202, ""));
        ArgumentCaptor<HttpRequest> posts = ArgumentCaptor.forClass(HttpRequest.class);

        try (SseScanSession session = newSession(Map.of())) {
            ProxyResponse result = session.forwardRequest(notification, Map.of());

            assertThat(result.statusCode()).isEqualTo(202);
            assertThat(result.body()).isEmpty();
            assertThat(session.pendingRequests()).isZero();
            verify(httpClient, times(4)).send(posts.capture(), any());
            assertThat(posts.getAllValues()).filteredOn(request -> "POST".equals(request.method()))
                    .hasSize(3);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardRequestRelaysANotificationRejection() throws Exception {
        String notification = "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}";
        HttpResponse<String> handshakeAccepted = mockPostResponse(202, "");
        HttpResponse<String> rejected = mockPostResponse(400, "{\"error\":\"bad\"}");
        HttpResponse<InputStream> sse = mockSseResponse(SSE_PRELUDE);
        java.util.concurrent.atomic.AtomicInteger postCount = new java.util.concurrent.atomic.AtomicInteger();
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if ("GET".equals(request.method())) {
                        return sse;
                    }
                    return postCount.incrementAndGet() <= 2 ? handshakeAccepted : rejected;
                });

        try (SseScanSession session = newSession(Map.of())) {
            ProxyResponse result = session.forwardRequest(notification, Map.of());

            assertThat(result.statusCode()).isEqualTo(400);
            assertThat(result.body()).isEqualTo("{\"error\":\"bad\"}");
        }
    }

    @Test
    void forwardRequestStillRejectsARequestWithANullOrMissingIdThatIsNotANotification() throws Exception {
        try (SseScanSession session = newSession(Map.of())) {
            assertThat(session.forwardRequest("{\"jsonrpc\":\"2.0\",\"id\":null,\"method\":\"ping\"}",
                    Map.of()).statusCode()).isEqualTo(400);
            assertThat(session.forwardRequest("{\"jsonrpc\":\"2.0\",\"result\":{}}", Map.of()).statusCode())
                    .isEqualTo(400);
            assertThat(session.forwardRequest("not json", Map.of()).statusCode()).isEqualTo(400);
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
    void repeaterOperationInheritsSessionAuthentication() throws Exception {
        stubHttpClient(mockSseResponse(SSE_PRELUDE + RESPONSE_EVENT), mockPostResponse());

        try (SseScanSession session = newSession(Map.of(
                "Authorization", "Bearer current-token", "X-Api-Key", "current-key"))) {
            session.forwardRequest(REQUEST_BODY, Map.of("X-Request", "repeater"));

            ArgumentCaptor<HttpRequest> requests = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(4)).send(requests.capture(), any());
            HttpRequest operation = requests.getAllValues().stream()
                    .filter(request -> request.headers().firstValue("X-Request").isPresent())
                    .findFirst().orElseThrow();
            assertThat(operation.headers().firstValue("Authorization")).contains("Bearer current-token");
            assertThat(operation.headers().firstValue("X-Api-Key")).contains("current-key");
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void repeaterOperationPreservesExplicitAuthenticationCaseInsensitively() throws Exception {
        stubHttpClient(mockSseResponse(SSE_PRELUDE + RESPONSE_EVENT), mockPostResponse());

        try (SseScanSession session = newSession(Map.of("Authorization", "Bearer session-token"))) {
            session.forwardRequest(REQUEST_BODY, Map.of("authorization", "Bearer explicit-token"));

            ArgumentCaptor<HttpRequest> requests = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(4)).send(requests.capture(), any());
            assertThat(requests.getAllValues().get(3).headers().allValues("Authorization"))
                    .containsExactly("Bearer explicit-token");
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void stripAuthSentinelSuppressesSessionAuthenticationOnOperationOnly() throws Exception {
        stubHttpClient(mockSseResponse(SSE_PRELUDE + RESPONSE_EVENT), mockPostResponse());

        try (SseScanSession session = newSession(Map.of(
                "Authorization", "Bearer session-token", "Cookie", "session=private",
                "X-Api-Key", "private-key", "MCP-Protocol-Version", "2025-06-18"))) {
            session.forwardRequest(REQUEST_BODY, Map.of("x-mcp-scanner-strip-auth", "1"));

            ArgumentCaptor<HttpRequest> requests = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(4)).send(requests.capture(), any());
            HttpRequest operation = requests.getAllValues().get(3);
            assertThat(operation.headers().firstValue("Authorization")).isEmpty();
            assertThat(operation.headers().firstValue("Cookie")).isEmpty();
            assertThat(operation.headers().firstValue("X-Api-Key")).isEmpty();
            assertThat(operation.headers().firstValue("x-mcp-scanner-strip-auth")).isEmpty();
            assertThat(operation.headers().firstValue("MCP-Protocol-Version")).contains("2025-06-18");
            assertThat(requests.getAllValues().get(0).headers().firstValue("Authorization"))
                    .contains("Bearer session-token");
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
    void rejectsCrossOriginEndpointBeforeSendingHandshake() throws Exception {
        stubHttpClient(mockSseResponse("event: endpoint\ndata: https://other.example/message\n\n"),
                mockPostResponse());

        try (SseScanSession session = newSession(Map.of())) {
            assertThatThrownBy(() -> session.forwardRequest(REQUEST_BODY, Map.of()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("cross-origin endpoint");
        }

        verify(httpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    void modeChangeDuringRedirectedSseHandshakePreventsMessagePost() throws Exception {
        URI reached = URI.create("http://127.0.0.1:3002/moved/stream");
        HttpResponse<InputStream> redirect = mock(HttpResponse.class);
        when(redirect.statusCode()).thenReturn(307);
        when(redirect.headers()).thenReturn(java.net.http.HttpHeaders.of(
                Map.of("Location", List.of(reached.toString())), (name, value) -> true));
        when(redirect.body()).thenReturn(new ByteArrayInputStream(new byte[0]));
        HttpResponse<InputStream> opened = mockSseResponse(
                "event: endpoint\ndata: message\n\n" + INITIALIZE_RESPONSE_EVENT + RESPONSE_EVENT);
        when(opened.uri()).thenReturn(reached);
        AtomicReference<RedirectMode> mode = new AtomicReference<>(RedirectMode.ALWAYS);
        AtomicInteger gets = new AtomicInteger();
        AtomicInteger posts = new AtomicInteger();
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if (!request.method().equals("GET")) {
                        posts.incrementAndGet();
                        return mockPostResponse();
                    }
                    if (gets.incrementAndGet() == 1) return redirect;
                    mode.set(RedirectMode.METHOD_PRESERVING_SAME_ORIGIN);
                    return opened;
                });

        try (SseScanSession session = newSession(Map.of("Authorization", "Bearer test"), mode::get)) {
            assertThatThrownBy(() -> session.forwardRequest(REQUEST_BODY, Map.of()))
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("Redirect mode changed");
        }
        assertThat(posts).hasValue(0);
    }

    @Test
    void redirectedSseStreamResolvesRelativeMessageEndpointAtReachedOrigin() throws Exception {
        URI reached = URI.create("http://localhost:3001/moved/stream");
        HttpResponse<InputStream> redirect = mock(HttpResponse.class);
        when(redirect.statusCode()).thenReturn(307);
        when(redirect.headers()).thenReturn(java.net.http.HttpHeaders.of(
                Map.of("Location", List.of(reached.toString())), (name, value) -> true));
        when(redirect.body()).thenReturn(new ByteArrayInputStream(new byte[0]));
        HttpResponse<InputStream> opened = mockSseResponse(
                "event: endpoint\ndata: message\n\n" + INITIALIZE_RESPONSE_EVENT + RESPONSE_EVENT);
        when(opened.uri()).thenReturn(reached);
        List<HttpRequest> sent = new java.util.concurrent.CopyOnWriteArrayList<>();
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    sent.add(request);
                    return request.method().equals("GET")
                            ? (sent.size() == 1 ? redirect : opened) : mockPostResponse();
                });

        try (SseScanSession session = newSession(Map.of("Authorization", "Bearer test"), () -> RedirectMode.SAME_ORIGIN)) {
            session.forwardRequest(REQUEST_BODY, Map.of());
        }

        assertThat(sent.stream().filter(request -> request.method().equals("POST"))
                .map(HttpRequest::uri)).allMatch(uri -> uri.toString().equals("http://localhost:3001/moved/message"));
    }

    @Test
    void alwaysModePostsToRedirectedCrossOriginSseEndpointWithConfiguredCredentials() throws Exception {
        URI reached = URI.create("http://127.0.0.1:3002/moved/stream");
        HttpResponse<InputStream> redirect = mock(HttpResponse.class);
        when(redirect.statusCode()).thenReturn(307);
        when(redirect.headers()).thenReturn(java.net.http.HttpHeaders.of(
                Map.of("Location", List.of(reached.toString())), (name, value) -> true));
        when(redirect.body()).thenReturn(new ByteArrayInputStream(new byte[0]));
        HttpResponse<InputStream> opened = mockSseResponse(
                "event: endpoint\ndata: message\n\n" + INITIALIZE_RESPONSE_EVENT + RESPONSE_EVENT);
        when(opened.uri()).thenReturn(reached);
        List<HttpRequest> sent = new java.util.concurrent.CopyOnWriteArrayList<>();
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    sent.add(request);
                    return request.method().equals("GET")
                            ? (sent.size() == 1 ? redirect : opened) : mockPostResponse();
                });

        try (SseScanSession session = newSession(Map.of("Authorization", "Bearer test"), () -> RedirectMode.ALWAYS)) {
            session.forwardRequest(REQUEST_BODY, Map.of());
        }

        assertThat(sent.stream().filter(request -> request.method().equals("POST")))
                .isNotEmpty().allMatch(request ->
                        request.uri().toString().equals("http://127.0.0.1:3002/moved/message")
                                && request.headers().firstValue("Authorization").orElse("")
                                .equals("Bearer test"));
    }

    @Test
    void invalidInitializeReplyDoesNotCompleteHandshake() throws Exception {
        String invalidPrelude = ENDPOINT_EVENT
                + "event: message\ndata: {\"jsonrpc\":\"1.0\",\"id\":" + HANDSHAKE_ID
                + ",\"result\":{}}\n\n";
        stubHttpClient(mockSseResponse(invalidPrelude), mockPostResponse());

        try (SseScanSession session = newSession(Map.of())) {
            assertThatThrownBy(() -> session.forwardRequest(REQUEST_BODY, Map.of()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("JSON-RPC version");
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
        HttpResponse<InputStream> sseResponse = openedByAGet(mock(HttpResponse.class));
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

                ProxyResponse responseB = doneWithin(futureB, ofSeconds(2)).get();
                assertThat(responseB.body()).contains("\"id\":2");
                assertThat(futureA.isDone()).isFalse();

                stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n");

                ProxyResponse responseA = doneWithin(futureA, ofSeconds(2)).get();
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

        try (SseScanSession session = TestSseSessions.builder(SSE_URL, httpClient).headers(Map.of()).requestIds(fixedHandshakeIdAllocator()).timeouts(Duration.ofMillis(150), Duration.ofSeconds(5)).eventLog(new McpEventLog(null)).build()) {
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

            ProxyResponse responseA = doneWithin(futureA, ofSeconds(1)).get();
            ProxyResponse responseB = doneWithin(futureB, ofSeconds(1)).get();
            assertThat(responseA.statusCode()).isEqualTo(502);
            assertThat(responseA.body()).contains("Session closed");
            assertThat(responseB.statusCode()).isEqualTo(502);
            assertThat(responseB.body()).contains("Session closed");
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void forwardRequest_pendingResponseBufferIsBoundedByBytesAndLogsEviction() throws Exception {
        String orphan = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{}}\n\n";
        long budget = 200;
        QueueInputStream stream = new QueueInputStream();
        stream.push(SSE_PRELUDE);
        for (int i = 1; i <= 20; i++) {
            stream.push(String.format(orphan, i));
        }
        String markerId = "21";
        stream.push(String.format(orphan, 21));
        stubHttpClient(mockSseResponse(stream), mockPostResponse());
        McpEventLog eventLog = new McpEventLog(null);

        try (SseScanSession session = TestSseSessions.builder(SSE_URL, httpClient).headers(Map.of()).requestIds(fixedHandshakeIdAllocator()).timeouts(ofSeconds(5), ofSeconds(5)).pendingResponseBudget(() -> budget).eventLog(eventLog).build()) {
            ProxyResponse response = session.forwardRequest(
                    "{\"jsonrpc\":\"2.0\",\"id\":" + markerId + ",\"method\":\"tools/call\",\"params\":{}}",
                    Map.of());

            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(session.pendingResponseBytes()).isLessThanOrEqualTo(budget);
            assertThat(eventLog.snapshot()).anySatisfy(entry ->
                    assertThat(entry.message()).contains("Unclaimed SSE response buffer"));
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

                ProxyResponse result = doneWithin(future, ofSeconds(2)).get();
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
                ProxyResponse result = doneWithin(future, ofSeconds(2)).get();
                assertThat(result.body()).isEqualTo(RESPONSE_JSON);
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardRequest_handshakeCarriesConfiguredClientProfile() throws Exception {
        QueueInputStream stream = new QueueInputStream();
        stream.push(ENDPOINT_EVENT);
        stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"serverInfo\":{\"name\":\"test\",\"version\":\"0\"}}}\n\n");
        stream.push("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[]}}\n\n");
        stubHttpClient(mockSseResponse(stream), mockPostResponse());
        var profile = ClientProfile.of(new ClientInfo("acme", "7", "Acme", null, "https://acme.example", null));

        try (SseScanSession session = TestSseSessions.builder(SSE_URL, httpClient).headers(Map.of()).requestIds(new AtomicLong(1)::getAndIncrement).clientProfile(() -> profile).eventLog(new McpEventLog(null)).build()) {
            session.forwardRequest("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{}}", Map.of());

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, atLeast(4)).send(captor.capture(), any());
            String initialize = captor.getAllValues().stream().filter(req -> "POST".equals(req.method()))
                    .map(SseProxyServerTest::extractBody).findFirst().orElseThrow();
            assertThat(initialize).contains("\"name\":\"acme\"").contains("\"title\":\"Acme\"")
                    .contains("\"websiteUrl\":\"https://acme.example\"");
        } finally {
            stream.close();
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

        try (SseScanSession session = TestSseSessions.builder(SSE_URL, httpClient).headers(Map.of()).requestIds(idAllocator).eventLog(new McpEventLog(null)).build()) {
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
    void forwardRequestHandshakesAfreshAfterEndpointEventTimedOut() throws Exception {
        QueueInputStream stalledStream = new QueueInputStream();
        stubSseStreams(mockSseResponse(stalledStream), mockSseResponse(SSE_PRELUDE + RESPONSE_EVENT));

        try (SseScanSession session = TestSseSessions.builder(SSE_URL, httpClient).headers(Map.of()).requestIds(fixedHandshakeIdAllocator()).timeouts(ofSeconds(5), ofMillis(150)).eventLog(new McpEventLog(null)).build()) {
            assertThatThrownBy(() -> session.forwardRequest(REQUEST_BODY, Map.of()))
                    .isInstanceOf(IOException.class);

            ProxyResponse recovered = session.forwardRequest(REQUEST_BODY, Map.of());

            assertThat(recovered.statusCode()).isEqualTo(200);
            assertThat(recovered.body()).isEqualTo(RESPONSE_JSON);
        } finally {
            stalledStream.close();
        }
    }

    @Test
    void forwardRequestHandshakesAfreshAfterInitializeFailed() throws Exception {
        stubSseStreams(mockSseResponse(ENDPOINT_EVENT), mockSseResponse(SSE_PRELUDE + RESPONSE_EVENT));

        try (SseScanSession session = newSession(Map.of())) {
            assertThatThrownBy(() -> session.forwardRequest(REQUEST_BODY, Map.of()))
                    .isInstanceOf(IOException.class);

            ProxyResponse recovered = session.forwardRequest(REQUEST_BODY, Map.of());

            assertThat(recovered.statusCode()).isEqualTo(200);
            assertThat(recovered.body()).isEqualTo(RESPONSE_JSON);
        }
    }

    @Test
    void closedSessionStaysClosedAfterFailedHandshake() throws Exception {
        stubHttpClient(mockSseResponse(ENDPOINT_EVENT), mockPostResponse());
        SseScanSession session = newSession(Map.of());
        assertThatThrownBy(() -> session.forwardRequest(REQUEST_BODY, Map.of()))
                .isInstanceOf(IOException.class);

        session.close();

        assertThat(session.forwardRequest(REQUEST_BODY, Map.of()).statusCode()).isEqualTo(502);
    }

    @SuppressWarnings("unchecked")
    private void stubSseStreams(HttpResponse<InputStream> first, HttpResponse<InputStream> second)
            throws IOException, InterruptedException {
        HttpResponse<String> postResponse = mockPostResponse();
        java.util.concurrent.atomic.AtomicInteger gets = new java.util.concurrent.atomic.AtomicInteger();
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if (!"GET".equals(request.method())) {
                        return postResponse;
                    }
                    return gets.getAndIncrement() == 0 ? first : second;
                });
    }

    @Test
    void ensureConnected_timesOutWhenInitializeResponseNeverArrives() throws Exception {
        // Endpoint event is delivered, but no initialize response is ever pushed.
        QueueInputStream stream = new QueueInputStream();
        stream.push(ENDPOINT_EVENT);
        stubHttpClient(mockSseResponse(stream), mockPostResponse());

        try (SseScanSession session = TestSseSessions.builder(SSE_URL, httpClient).headers(Map.of()).requestIds(fixedHandshakeIdAllocator()).timeouts(Duration.ofSeconds(5), Duration.ofMillis(150)).eventLog(new McpEventLog(null)).build()) {
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

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(ints = {400, 429, 503})
    @SuppressWarnings("unchecked")
    void forwardRequest_relaysTheServersRefusalOfTheSseStreamOpen(int status) throws Exception {
        HttpResponse<InputStream> refusedStream = mockSseResponseWithStatus(status, "{\"error\":\"refused\"}");
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(refusedStream);

        try (SseScanSession session = newSession(Map.of())) {
            ProxyResponse result = session.forwardRequest(REQUEST_BODY, Map.of());

            assertThat(result.statusCode()).isEqualTo(status);
            assertThat(result.body()).isEqualTo("{\"error\":\"refused\"}");
            verify(httpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        }
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({"initialize,429", "initialize,400",
            "notifications/initialized,503"})
    @SuppressWarnings("unchecked")
    void forwardRequest_relaysTheServersRefusalOfAHandshakePost(String stage, int status) throws Exception {
        QueueInputStream stream = new QueueInputStream();
        stream.push(SSE_PRELUDE);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> {
                    HttpRequest request = invocation.getArgument(0);
                    if ("GET".equals(request.method())) {
                        return mockSseResponse(stream);
                    }
                    String body = SseProxyServerTest.extractBody(request);
                    return body.contains("\"method\":\"" + stage + "\"")
                            ? mockPostResponse(status, "{\"error\":\"refused\"}") : mockPostResponse(202, "");
                });

        try (SseScanSession session = newSession(Map.of(), Duration.ofMillis(500))) {
            ProxyResponse result = session.forwardRequest(REQUEST_BODY, Map.of());

            assertThat(result.statusCode()).isEqualTo(status);
            assertThat(result.body()).isEqualTo("{\"error\":\"refused\"}");
        } finally {
            stream.close();
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
        AtomicBoolean disconnectDone = new AtomicBoolean();
        ExecutorService disconnector = Executors.newSingleThreadExecutor();
        try {
            disconnector.submit(() -> {
                try {
                    session.close();
                } catch (Exception ignored) {
                }
                disconnectDone.set(true);
            });

            // The session closes the stream inside its synchronized teardown, after the closed flag is set.
            await().atMost(ofSeconds(2)).pollInterval(ofMillis(10)).until(stream::isClosed);

            // A concurrent forwardRequest should return quickly (within 100 ms),
            // NOT block for up to 1 s waiting to acquire 'this'.
            long before = System.nanoTime();
            ProxyResponse result = session.forwardRequest(
                    "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{}}", Map.of());
            long elapsedMs = (System.nanoTime() - before) / 1_000_000;

            assertThat(result.statusCode()).isEqualTo(502);
            assertThat(result.body()).contains("Session closed");
            assertThat(elapsedMs).as("forwardRequest should return fast while disconnect holds join").isLessThan(100);

            await().atMost(ofSeconds(3)).pollInterval(ofMillis(10)).untilTrue(disconnectDone);
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

        boolean isClosed() {
            return closed;
        }
    }
}
