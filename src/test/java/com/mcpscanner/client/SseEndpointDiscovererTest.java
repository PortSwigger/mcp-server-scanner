package com.mcpscanner.client;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.http.evidence.WireRecord;
import com.mcpscanner.mcp.RawSseFrame;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.config.RedirectMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

@ExtendWith(MockitoExtension.class)
class SseEndpointDiscovererTest {

    private static final Duration DISCOVERY_TIMEOUT = Duration.ofSeconds(2);

    @Mock private Logging logging;
    @Mock private HttpClient httpClient;

    private SseEndpointDiscoverer discoverer;

    @BeforeEach
    void setUp() {
        discoverer = new SseEndpointDiscoverer(httpClient, McpEventLog.noop());
    }

    @Test
    void discoverReturnsMessageUrlFromFirstEvent() {
        String body = "event: endpoint\ndata: /custom/message\n\n";
        stubSseResponse(200, body);

        SseEndpointDiscoverer.DiscoveryResult result = discoverer.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT);

        assertThat(result.messageUrl().toString()).isEqualTo("http://127.0.0.1:9000/custom/message");
        assertThat(result.sseStream()).isNotNull();
    }

    @Test
    void carriesTheGetThatOpenedTheStreamAndTheStreamsRealStatusAndHeaders() throws Exception {
        MontoyaTestFactory.install();
        String frame = "id: 1\r\nevent: message\r\ndata: {}\r\n\r\n";
        try (McpFixtureServer server = new McpFixtureServer(McpFixtureProfile.sseOnly("2024-11-05"))) {
            SseEndpointDiscoverer.DiscoveryResult result = new SseEndpointDiscoverer(McpHttpClients.upstream(),
                    McpEventLog.noop()).discover(URI.create(server.endpoint()),
                    Map.of("Authorization", "Bearer bob"), DISCOVERY_TIMEOUT);

            try (InputStream ignored = result.sseStream()) {
                HttpRequestResponse evidence = result.opening().evidenceOf(
                        WireRecord.unanswered(HttpService.httpService("127.0.0.1", 1, false),
                                "POST /messages HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".getBytes(StandardCharsets.UTF_8)),
                        new RawSseFrame("", frame.getBytes(StandardCharsets.UTF_8))).get(1);
                assertThat(evidence.request().method()).isEqualTo("GET");
                assertThat(evidence.request().url()).isEqualTo(server.endpoint());
                assertThat(evidence.request().headerValue("Authorization")).isEqualTo("Bearer bob");
                assertThat(text(evidence.request().toByteArray())).contains("Host: 127.0.0.1:", "User-Agent: Java-http-client/");
                assertThat(evidence.response().statusCode()).isEqualTo((short) 200);
                assertThat(evidence.response().headerValue("Content-Type")).isEqualTo("text/event-stream");
                assertThat(evidence.response().bodyToString()).isEqualTo(frame);
            }
        }
    }

    @Test
    void discoversEndpointWithMixedLineEndingTerminator() {
        stubSseResponse(200, "event: endpoint\ndata: /custom/message\n\r");

        SseEndpointDiscoverer.DiscoveryResult result = discoverer.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT);

        assertThat(result.messageUrl().toString()).isEqualTo("http://127.0.0.1:9000/custom/message");
    }

    @Test
    void discoversEndpointAfterCrLfKeepaliveEventsWithinEventLimit() {
        stubSseResponse(200, ": keepalive\r\n\r\n".repeat(16)
                + "event: endpoint\r\ndata: /custom/message\r\n\r\n");

        SseEndpointDiscoverer.DiscoveryResult result = discoverer.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT);

        assertThat(result.messageUrl().toString()).isEqualTo("http://127.0.0.1:9000/custom/message");
    }

    @Test
    void preservesRemainingStreamAfterCrLfEndpointTerminator() throws Exception {
        String nextEvent = "event: message\r\ndata: {\"id\":1,\"result\":{}}\r\n\r\n";
        stubSseResponse(200, "event: endpoint\r\ndata: /custom/message\r\n\r\n" + nextEvent);

        SseEndpointDiscoverer.DiscoveryResult result = discoverer.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT);

        assertThat(new String(result.sseStream().readAllBytes(), StandardCharsets.UTF_8)).isEqualTo(nextEvent);
    }

    @Test
    void discoverRejectsCrossHostEndpoint() {
        String body = "event: endpoint\ndata: http://evil.example.com/message\n\n";
        stubSseResponse(200, body);

        assertThatThrownBy(() -> discoverer.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("cross-origin");
    }

    @Test
    void discoverRejectsSameHostEndpointOnDifferentPort() {
        stubSseResponse(200, "event: endpoint\ndata: http://127.0.0.1:9001/message\n\n");

        assertThatThrownBy(() -> discoverer.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("cross-origin");
    }

    @Test
    void discoverRejectsSameHostEndpointWithSchemeDowngrade() {
        stubSseResponse(200, "event: endpoint\ndata: http://mcp.example.com/message\n\n");

        assertThatThrownBy(() -> discoverer.discover(
                URI.create("https://mcp.example.com/sse"), Map.of(), DISCOVERY_TIMEOUT))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("cross-origin");
    }

    @Test
    void discoverAcceptsEndpointWithExplicitDefaultPortAndMixedCaseHost() {
        stubSseResponse(200, "event: endpoint\ndata: https://MCP.example.com:443/message\n\n");

        SseEndpointDiscoverer.DiscoveryResult result = discoverer.discover(
                URI.create("https://mcp.example.com/sse"), Map.of(), DISCOVERY_TIMEOUT);

        assertThat(result.messageUrl().toString()).isEqualTo("https://mcp.example.com/message");
    }

    @Test
    void discoverFailsOnTimeoutWithoutLiveStream() {
        CompletableFuture<HttpResponse<InputStream>> failing = new CompletableFuture<>();
        failing.completeExceptionally(new HttpTimeoutException("timed out"));
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(failing);

        assertThatThrownBy(() -> discoverer.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("discovery failed");
    }

    @Test
    @SuppressWarnings("unchecked")
    void discoverClosesResponseBodyOnTimeout() throws Exception {
        InputStream body = mock(InputStream.class);
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        lenient().when(response.body()).thenReturn(body);
        lenient().when(response.statusCode()).thenReturn(200);

        CompletableFuture<HttpResponse<InputStream>> future = new CompletableFuture<>();
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(future);

        Thread caller = new Thread(() ->
                discoverer.discover(URI.create("http://127.0.0.1:9000/sse"), Map.of(), Duration.ofMillis(50)));
        caller.start();
        await().atMost(2, SECONDS).pollInterval(10, MILLISECONDS).dontCatchUncaughtExceptions()
                .until(() -> !caller.isAlive());

        assertThat(future.isCancelled() || future.isCompletedExceptionally()).isTrue();
    }

    @Test
    void discoverFailureLogsWarningWithoutFallbackSuccess() {
        CompletableFuture<HttpResponse<InputStream>> failing = new CompletableFuture<>();
        failing.completeExceptionally(new HttpTimeoutException("timed out"));
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(failing);
        McpEventLog eventLog = new McpEventLog(null);
        SseEndpointDiscoverer withEventLog = new SseEndpointDiscoverer(httpClient, eventLog);

        assertThatThrownBy(() -> withEventLog.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT))
                .isInstanceOf(IllegalStateException.class);

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("SSE endpoint discovery failed"));
        assertThat(eventLog.snapshot())
                .noneMatch(entry -> entry.message().contains("Using fallback SSE message endpoint"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void discoverStopsReadingOversizedEndpointScanAndFails() {
        byte[] giant = ("event: notendpoint\ndata: " + "a".repeat(2 * 1024 * 1024) + "\n\n")
                .getBytes(StandardCharsets.UTF_8);
        CountingInputStream body = new CountingInputStream(giant);
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        lenient().when(response.body()).thenReturn(body);
        lenient().when(response.statusCode()).thenReturn(200);
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(response));

        assertThatThrownBy(() -> discoverer.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("exceeded");
        assertThat(body.bytesRead()).isLessThan(giant.length);
    }

    @Test
    void boundedFallbackPreservesLiveStreamAfterNonEndpointEvents() throws Exception {
        byte[] precedingEvents = "event: ping\ndata: alive\n\n".repeat(32).getBytes(StandardCharsets.UTF_8);
        byte[] subsequentReply = "event: message\ndata: later\n\n".getBytes(StandardCharsets.UTF_8);
        byte[] allEvents = new byte[precedingEvents.length + subsequentReply.length];
        System.arraycopy(precedingEvents, 0, allEvents, 0, precedingEvents.length);
        System.arraycopy(subsequentReply, 0, allEvents, precedingEvents.length, subsequentReply.length);
        stubSseResponse(200, new String(allEvents, StandardCharsets.UTF_8));

        SseEndpointDiscoverer.DiscoveryResult result = discoverer.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT);

        assertThat(result.messageUrl().toString()).isEqualTo("http://127.0.0.1:9000/message");
        assertThat(result.sseStream()).isNotNull();
        assertThat(result.sseStream().readAllBytes()).isEqualTo(subsequentReply);
    }

    @Test
    void fallbackRetainsQueryOnMessageEndpoint() {
        stubSseResponse(200, "event: ping\ndata: alive\n\n".repeat(32));

        SseEndpointDiscoverer.DiscoveryResult result = discoverer.discover(
                URI.create("http://127.0.0.1:9000/api/sse?token=abc"), Map.of(), DISCOVERY_TIMEOUT);

        assertThat(result.messageUrl().toString())
                .isEqualTo("http://127.0.0.1:9000/api/message?token=abc");
        assertThat(result.sseStream()).isNotNull();
    }

    @Test
    void closedStreamWithoutEndpointFailsExplicitly() {
        stubSseResponse(200, "event: ping\ndata: alive\n\n");

        assertThatThrownBy(() -> discoverer.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("closed");
    }

    @Test
    @SuppressWarnings("unchecked")
    void openStreamWithoutEventsTimesOutAndCloses() {
        CountDownLatch closed = new CountDownLatch(1);
        InputStream openStream = new InputStream() {
            @Override public int read() throws IOException {
                try {
                    closed.await();
                    return -1;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException(e);
                }
            }
            @Override public void close() { closed.countDown(); }
        };
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        lenient().when(response.body()).thenReturn(openStream);
        lenient().when(response.statusCode()).thenReturn(200);
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(response));

        assertTimeoutPreemptively(Duration.ofSeconds(2), () ->
                assertThatThrownBy(() -> discoverer.discover(
                        URI.create("http://127.0.0.1:9000/sse"), Map.of(), Duration.ofMillis(50)))
                        .isInstanceOf(IllegalStateException.class));
        assertThat(closed.getCount()).isZero();
    }

    @Test
    void carriageReturnDelimitedEndpointEventIsAccepted() {
        stubSseResponse(200, "event: endpoint\rdata: /custom/message\r\r");

        SseEndpointDiscoverer.DiscoveryResult result = discoverer.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT);

        assertThat(result.messageUrl().toString()).isEqualTo("http://127.0.0.1:9000/custom/message");
    }

    @Test
    void discoverPropagatesAuthHeaders() {
        stubSseResponse(200, "event: endpoint\ndata: /msg\n\n");

        discoverer.discover(URI.create("http://127.0.0.1:9000/sse"),
                Map.of("Authorization", "Bearer xyz"), DISCOVERY_TIMEOUT);

        ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient, atLeastOnce()).sendAsync(captor.capture(), any(HttpResponse.BodyHandler.class));
        assertThat(captor.getValue().headers().firstValue("Authorization")).contains("Bearer xyz");
    }

    @Test
    @SuppressWarnings("unchecked")
    void discoveryFollowsSameOriginRedirectWhenSelected() {
        HttpResponse<InputStream> redirect = mock(HttpResponse.class);
        when(redirect.statusCode()).thenReturn(307);
        when(redirect.headers()).thenReturn(HttpHeaders.of(Map.of("Location", java.util.List.of("/moved")),
                (name, value) -> true));
        lenient().when(redirect.body()).thenReturn(new ByteArrayInputStream(new byte[0]));
        HttpResponse<InputStream> stream = mock(HttpResponse.class);
        when(stream.statusCode()).thenReturn(200);
        when(stream.uri()).thenReturn(URI.create("http://127.0.0.1:9000/moved/stream"));
        when(stream.body()).thenReturn(new ByteArrayInputStream(
                "event: endpoint\ndata: message\n\n".getBytes(StandardCharsets.UTF_8)));
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(redirect), CompletableFuture.completedFuture(stream));
        SseEndpointDiscoverer discoverer = new SseEndpointDiscoverer(httpClient, McpEventLog.noop(),
                new RedirectLoggingInterceptor(McpEventLog.noop(), () -> RedirectMode.SAME_ORIGIN));

        SseEndpointDiscoverer.DiscoveryResult result = discoverer.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of("Authorization", "Bearer secret"), DISCOVERY_TIMEOUT);

        assertThat(result.messageUrl()).isEqualTo(URI.create("http://127.0.0.1:9000/moved/message"));
        ArgumentCaptor<HttpRequest> sent = ArgumentCaptor.forClass(HttpRequest.class);
        verify(httpClient, org.mockito.Mockito.times(2)).sendAsync(sent.capture(), any());
        assertThat(sent.getAllValues().get(1).uri()).isEqualTo(URI.create("http://127.0.0.1:9000/moved"));
        assertThat(sent.getAllValues().get(1).headers().firstValue("Authorization")).contains("Bearer secret");
    }

    @SuppressWarnings("unchecked")
    private void stubSseResponse(int status, String body) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        lenient().when(response.body()).thenReturn(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        lenient().when(response.statusCode()).thenReturn(status);
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(response));
    }

    private static final class CountingInputStream extends ByteArrayInputStream {
        private int bytesRead;

        CountingInputStream(byte[] data) {
            super(data);
        }

        @Override
        public synchronized int read() {
            int value = super.read();
            if (value != -1) {
                bytesRead++;
            }
            return value;
        }

        @Override
        public synchronized int read(byte[] b, int off, int len) {
            int count = super.read(b, off, len);
            if (count > 0) {
                bytesRead += count;
            }
            return count;
        }

        int bytesRead() {
            return bytesRead;
        }
    }

    private static String text(burp.api.montoya.core.ByteArray bytes) {
        return new String(bytes.getBytes(), java.nio.charset.StandardCharsets.ISO_8859_1);
    }
}
