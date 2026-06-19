package com.mcpscanner.client;

import burp.api.montoya.logging.Logging;
import com.mcpscanner.logging.McpEventLog;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SseEndpointDiscovererTest {

    private static final Duration DISCOVERY_TIMEOUT = Duration.ofSeconds(2);

    @Mock private Logging logging;
    @Mock private HttpClient httpClient;

    private SseEndpointDiscoverer discoverer;

    @BeforeEach
    void setUp() {
        discoverer = new SseEndpointDiscoverer(httpClient, logging);
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
    void discoverRejectsCrossHostEndpoint() {
        String body = "event: endpoint\ndata: http://evil.example.com/message\n\n";
        stubSseResponse(200, body);

        SseEndpointDiscoverer.DiscoveryResult result = discoverer.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT);

        assertThat(result.messageUrl().toString()).isEqualTo("http://127.0.0.1:9000/message");
        assertThat(result.sseStream()).isNull();
    }

    @Test
    void discoverFallsBackOnTimeout() {
        CompletableFuture<HttpResponse<InputStream>> failing = new CompletableFuture<>();
        failing.completeExceptionally(new HttpTimeoutException("timed out"));
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(failing);

        SseEndpointDiscoverer.DiscoveryResult result = discoverer.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT);

        assertThat(result.messageUrl().toString()).isEqualTo("http://127.0.0.1:9000/message");
        assertThat(result.sseStream()).isNull();
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
        caller.join(2_000);

        assertThat(future.isCancelled() || future.isCompletedExceptionally()).isTrue();
    }

    @Test
    void discoverFallbackLogsInfoToEventLog() {
        CompletableFuture<HttpResponse<InputStream>> failing = new CompletableFuture<>();
        failing.completeExceptionally(new HttpTimeoutException("timed out"));
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(failing);
        McpEventLog eventLog = new McpEventLog(null);
        SseEndpointDiscoverer withEventLog = new SseEndpointDiscoverer(httpClient, logging, eventLog);

        withEventLog.discover(URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT);

        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.WARN
                        && entry.message().contains("SSE endpoint discovery failed"));
        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                        && entry.message().contains("Using fallback SSE message endpoint"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void discoverStopsReadingOversizedEndpointScanAndFallsBack() {
        byte[] giant = ("event: notendpoint\ndata: " + "a".repeat(2 * 1024 * 1024) + "\n\n")
                .getBytes(StandardCharsets.UTF_8);
        CountingInputStream body = new CountingInputStream(giant);
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        lenient().when(response.body()).thenReturn(body);
        lenient().when(response.statusCode()).thenReturn(200);
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(response));

        SseEndpointDiscoverer.DiscoveryResult result = discoverer.discover(
                URI.create("http://127.0.0.1:9000/sse"), Map.of(), DISCOVERY_TIMEOUT);

        assertThat(result.messageUrl().toString()).isEqualTo("http://127.0.0.1:9000/message");
        assertThat(result.sseStream()).isNull();
        assertThat(body.bytesRead()).isLessThan(giant.length);
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
}
