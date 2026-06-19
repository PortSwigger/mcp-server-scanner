package com.mcpscanner.proxy;

import burp.api.montoya.logging.Logging;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.logging.McpEventLog;
import fi.iki.elonen.NanoHTTPD;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
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
import java.util.concurrent.TimeUnit;

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
        eventLog = new McpEventLog(null);
        lenient().when(scannerSession.eventLog()).thenReturn(eventLog);
    }

    @Test
    void startsAndStopsWithoutError() throws Exception {
        SseProxyServer proxy = new SseProxyServer(scannerSession, logging);
        proxy.start();
        assertThat(proxy.port()).isGreaterThan(0);
        proxy.stop();
    }

    @Test
    void convertsStreamingSseResponseToJson() throws IOException {
        String sseBody = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        InputStream stream = new ByteArrayInputStream(sseBody.getBytes());

        ProxyResponse result = SseProxyServer.convertStreamingResponse(200, "text/event-stream", stream);

        assertThat(result.statusCode()).isEqualTo(200);
        assertThat(result.contentType()).isEqualTo("application/json");
        assertThat(result.body()).isEqualTo("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
    }

    @Test
    void returnsJsonResponseUnchangedFromStream() throws IOException {
        String jsonBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
        InputStream stream = new ByteArrayInputStream(jsonBody.getBytes());

        ProxyResponse result = SseProxyServer.convertStreamingResponse(200, "application/json", stream);

        assertThat(result.statusCode()).isEqualTo(200);
        assertThat(result.contentType()).isEqualTo("application/json");
        assertThat(result.body()).isEqualTo(jsonBody);
    }

    @Test
    void returnsEmptyBodyWhenSseParsingYieldsNull() throws IOException {
        String sseBody = "event: endpoint\ndata: /message\n\n";
        InputStream stream = new ByteArrayInputStream(sseBody.getBytes());

        ProxyResponse result = SseProxyServer.convertStreamingResponse(200, "text/event-stream", stream);

        assertThat(result.body()).isEmpty();
    }

    @Test
    void sseStreamingResponseReturnsAsSoonAsCompleteEventArrivesWithoutWaitingForEof() throws Exception {
        String completedEvent = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        PipedOutputStream upstream = new PipedOutputStream();
        PipedInputStream stream = new PipedInputStream(upstream, 64 * 1024);
        upstream.write(completedEvent.getBytes(StandardCharsets.UTF_8));
        upstream.flush();
        // Deliberately do not close upstream — readAllBytes() would block forever here.

        ProxyResponse result = CompletableFuture
                .supplyAsync(() -> {
                    try {
                        return SseProxyServer.convertStreamingResponse(200, "text/event-stream", stream);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                })
                .get(5, TimeUnit.SECONDS);

        assertThat(result.contentType()).isEqualTo("application/json");
        assertThat(result.body()).isEqualTo("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        upstream.close();
    }

    @Test
    void sseEventExceedingCapFailsWithBoundedProxyError() {
        StringBuilder huge = new StringBuilder("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"big\":\"");
        huge.append("a".repeat(2 * 1024 * 1024));
        huge.append("\"}\n\n");
        InputStream stream = new ByteArrayInputStream(huge.toString().getBytes(StandardCharsets.UTF_8));

        org.assertj.core.api.Assertions.assertThatThrownBy(
                () -> SseProxyServer.convertStreamingResponse(200, "text/event-stream", stream))
                .isInstanceOf(IOException.class);
    }

    @Test
    void nonSseResponseExceedingCapIsRejected() {
        byte[] huge = new byte[9 * 1024 * 1024];
        java.util.Arrays.fill(huge, (byte) 'x');
        InputStream stream = new ByteArrayInputStream(huge);

        org.assertj.core.api.Assertions.assertThatThrownBy(
                () -> SseProxyServer.convertStreamingResponse(200, "application/json", stream))
                .isInstanceOf(IOException.class);
    }

    @Test
    void servesSseTransportViaSseScanSession() throws Exception {
        SseScanSession sseScanSession = mock(SseScanSession.class);
        HttpClient httpClient = mock(HttpClient.class);
        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, sseScanSession, logging);

        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:8080/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.nextRequestId()).thenReturn(42L);

        String requestBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}";
        ProxyResponse expectedResponse =
                new ProxyResponse(200, "application/json", "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        when(sseScanSession.forwardRequest(anyString(), anyMap())).thenReturn(expectedResponse);

        NanoHTTPD.IHTTPSession session = mockIHttpSession(requestBody);

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
        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, sseScanSession, logging);

        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:8080/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.nextRequestId()).thenReturn(7L, 8L, 9L);
        when(sseScanSession.forwardRequest(anyString(), anyMap())).thenReturn(
                new ProxyResponse(200, "application/json", "{}"));

        String originalBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}";

        proxy.start();
        try {
            proxy.serve(mockIHttpSession(originalBody));
            proxy.serve(mockIHttpSession(originalBody));
            proxy.serve(mockIHttpSession(originalBody));

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
        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, sseScanSession, logging);

        proxy.start();
        proxy.stop();

        verify(sseScanSession).close();
    }

    @Test
    void closingScanSessionIoExceptionIsLogged() throws Exception {
        SseScanSession sseScanSession = mock(SseScanSession.class);
        HttpClient httpClient = mock(HttpClient.class);
        doThrow(new IOException("socket broken")).when(sseScanSession).close();
        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, sseScanSession, logging);

        proxy.resetScanSession();

        verify(logging).logToError(contains("socket broken"));
    }

    @Test
    void resetScanSessionClosesCachedSessionSoNextScanTargetsNewServer() throws Exception {
        SseScanSession firstSession = mock(SseScanSession.class);
        HttpClient httpClient = mock(HttpClient.class);
        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, firstSession, logging);

        String requestBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}";
        when(scannerSession.resolvedEndpoint()).thenReturn("http://first.example/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.nextRequestId()).thenReturn(42L);
        when(firstSession.forwardRequest(anyString(), anyMap())).thenReturn(
                new ProxyResponse(200, "application/json", "{}"));

        NanoHTTPD.IHTTPSession session = mockIHttpSession(requestBody);

        proxy.start();
        try {
            proxy.serve(session);
            verify(firstSession).forwardRequest(anyString(), anyMap());

            proxy.resetScanSession();
            verify(firstSession).close();

            when(scannerSession.resolvedEndpoint()).thenReturn("http://second.example/sse");
            when(scannerSession.sseUrl()).thenReturn("http://second.example/sse");

            proxy.serve(mockIHttpSession(requestBody));

            verifyNoMoreInteractions(firstSession);
        } finally {
            proxy.stop();
        }
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
        lenient().when(session.getHeaders()).thenReturn(headers);
        lenient().doAnswer(invocation -> {
            Map<String, String> body = invocation.getArgument(0);
            body.put("postData", requestBody);
            return null;
        }).when(session).parseBody(any());
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
    void serveStreamableHttp_retriesOnceOnSessionNotFound_returnsRetryResponse() throws Exception {
        String sessionNotFoundBody = "{\"jsonrpc\":\"2.0\",\"id\":\"server-error\",\"error\":{\"code\":-32600,\"message\":\"Session not found\"}}";
        String successBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}";

        HttpResponse<InputStream> failureResponse = mockStreamResponse(404, "application/json", sessionNotFoundBody);
        HttpResponse<InputStream> successResponse = mockStreamResponse(200, "application/json", successBody);
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(failureResponse, successResponse);
        when(scannerSession.refreshScannerSession()).thenReturn(true);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of("Mcp-Session-Id", "refreshed"));

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession("{}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            assertThat(new String(response.getData().readAllBytes())).isEqualTo(successBody);
            verify(scannerSession, times(1)).refreshScannerSession();
            verify(httpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void serveStreamableHttp_doesNotRetryIfRefreshFails() throws Exception {
        String sessionNotFoundBody = "{\"jsonrpc\":\"2.0\",\"id\":\"server-error\",\"error\":{\"code\":-32600,\"message\":\"Session not found\"}}";

        HttpResponse<InputStream> failureResponse = mockStreamResponse(404, "application/json", sessionNotFoundBody);
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(failureResponse);
        when(scannerSession.refreshScannerSession()).thenReturn(false);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession("{}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(404);
            assertThat(new String(response.getData().readAllBytes())).isEqualTo(sessionNotFoundBody);
            verify(scannerSession).refreshScannerSession();
            verify(httpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
            verify(logging).logToError(contains("Scanner session refresh failed"));
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void serveStreamableHttp_retriesOnSessionNotFoundWithPrettyPrintedBody() throws Exception {
        String prettyBody = "{\n  \"jsonrpc\": \"2.0\",\n  \"id\": \"server-error\",\n  \"error\": {\n    \"code\": -32600,\n    \"message\": \"Session not found\"\n  }\n}";
        String successBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";

        HttpResponse<InputStream> failureResponse = mockStreamResponse(404, "application/json", prettyBody);
        HttpResponse<InputStream> successResponse = mockStreamResponse(200, "application/json", successBody);
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(failureResponse, successResponse);
        when(scannerSession.refreshScannerSession()).thenReturn(true);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession("{}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            assertThat(new String(response.getData().readAllBytes())).isEqualTo(successBody);
            verify(scannerSession, times(1)).refreshScannerSession();
            verify(httpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void serveStreamableHttp_givesUpAfterOneRetryOnRepeatedSessionNotFound_returnsLast404() throws Exception {
        String firstBody = "{\"jsonrpc\":\"2.0\",\"id\":\"first\",\"error\":{\"code\":-32600,\"message\":\"Session not found\"}}";
        String retryBody = "{\"jsonrpc\":\"2.0\",\"id\":\"retry\",\"error\":{\"code\":-32600,\"message\":\"Session not found\"}}";

        HttpResponse<InputStream> firstResponse = mockStreamResponse(404, "application/json", firstBody);
        HttpResponse<InputStream> retryResponse = mockStreamResponse(404, "application/json", retryBody);
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(firstResponse, retryResponse);
        when(scannerSession.refreshScannerSession()).thenReturn(true);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession("{}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(404);
            assertThat(new String(response.getData().readAllBytes())).isEqualTo(retryBody);
            verify(scannerSession, times(1)).refreshScannerSession();
            verify(httpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void serveStreamableHttp_doesNotRetryOnNon404Errors() throws Exception {
        String errorBody = "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32603,\"message\":\"Internal error\"}}";

        HttpResponse<InputStream> errorResponse = mockStreamResponse(500, "application/json", errorBody);
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(errorResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession("{}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(500);
            assertThat(new String(response.getData().readAllBytes())).isEqualTo(errorBody);
            verify(scannerSession, never()).refreshScannerSession();
            verify(httpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
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
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> mockStreamResponse(200, "application/json", successBody));
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());
        when(scannerSession.nextRequestId()).thenReturn(7L, 8L, 9L);

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        proxy.start();
        try {
            proxy.serve(mockIHttpSession(originalBody));
            proxy.serve(mockIHttpSession(originalBody));
            proxy.serve(mockIHttpSession(originalBody));

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient, times(3)).send(captor.capture(), any(HttpResponse.BodyHandler.class));

            List<String> forwardedBodies = captor.getAllValues().stream()
                    .map(SseProxyServerTest::extractBody)
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
    void serveStreamableHttp_doesNotRetryOn404WithoutJsonRpcErrorCode() throws Exception {
        String genericNotFoundBody = "Not Found";

        HttpResponse<InputStream> notFoundResponse = mockStreamResponse(404, "text/plain", genericNotFoundBody);
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(notFoundResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession("{}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(404);
            assertThat(new String(response.getData().readAllBytes())).isEqualTo(genericNotFoundBody);
            verify(scannerSession, never()).refreshScannerSession();
            verify(httpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
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
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> mockStreamResponse(200, "application/json", successBody));
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        proxy.start();
        try {
            proxy.serve(mockIHttpSession(notificationBody));

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient).send(captor.capture(), any(HttpResponse.BodyHandler.class));

            assertThat(extractBody(captor.getValue())).isEqualTo(notificationBody);
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
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenAnswer(invocation -> mockStreamResponse(200, "application/json", successBody));
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession(malformedBody));

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertThat(extractBody(captor.getValue())).isEqualTo(malformedBody);
            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            verify(logging).logToError(contains("rewrite JSON-RPC id"));
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
    void serveStreamableHttp_retriesOnceOn401AfterAuthRefresh() throws Exception {
        String unauthorizedBody = "{\"error\":\"invalid_token\"}";
        String successBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";

        HttpResponse<InputStream> failureResponse = mockStreamResponse(401, "application/json", unauthorizedBody);
        HttpResponse<InputStream> successResponse = mockStreamResponse(200, "application/json", successBody);
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(failureResponse, successResponse);
        when(scannerSession.refreshAuth()).thenReturn(true);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession("{}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            assertThat(new String(response.getData().readAllBytes())).isEqualTo(successBody);
            verify(scannerSession, times(1)).refreshAuth();
            verify(httpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
            ArgumentCaptor<String> outputMessage = ArgumentCaptor.forClass(String.class);
            verify(logging).logToOutput(outputMessage.capture());
            assertThat(outputMessage.getValue()).doesNotContain("OAuth");
            assertThat(eventLog.snapshot())
                    .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                            && entry.message().contains("Authentication refresh after 401, retrying"));
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void scannerSessionRefreshFailureLogsErrorToEventLog() throws Exception {
        String sessionNotFoundBody = "{\"jsonrpc\":\"2.0\",\"id\":\"server-error\",\"error\":{\"code\":-32600,\"message\":\"Session not found\"}}";

        HttpResponse<InputStream> failureResponse = mockStreamResponse(404, "application/json", sessionNotFoundBody);
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(failureResponse);
        when(scannerSession.refreshScannerSession()).thenReturn(false);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        proxy.start();
        try {
            proxy.serve(mockIHttpSession("{}"));

            assertThat(eventLog.snapshot())
                    .anyMatch(entry -> entry.level() == McpEventLog.Level.ERROR
                            && entry.message().contains("Scanner session refresh failed"));
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void serveStreamableHttp_doesNotRetry401WhenAuthRefreshFails() throws Exception {
        String unauthorizedBody = "{\"error\":\"invalid_token\"}";

        HttpResponse<InputStream> failureResponse = mockStreamResponse(401, "application/json", unauthorizedBody);
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(failureResponse);
        when(scannerSession.refreshAuth()).thenReturn(false);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession("{}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(401);
            verify(scannerSession, times(1)).refreshAuth();
            verify(httpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
            ArgumentCaptor<String> errorMessage = ArgumentCaptor.forClass(String.class);
            verify(logging).logToError(errorMessage.capture());
            assertThat(errorMessage.getValue()).doesNotContain("OAuth").startsWith("Auth refresh failed");
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void serveStreamableHttp_propagates401WhenRetryStillUnauthorized() throws Exception {
        String unauthorizedBody = "{\"error\":\"invalid_token\"}";

        HttpResponse<InputStream> first = mockStreamResponse(401, "application/json", unauthorizedBody);
        HttpResponse<InputStream> retry = mockStreamResponse(401, "application/json", unauthorizedBody);
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(first, retry);
        when(scannerSession.refreshAuth()).thenReturn(true);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession("{}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(401);
            verify(scannerSession, times(1)).refreshAuth();
            verify(httpClient, times(2)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
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
        java.util.Queue<SseScanSession> sessions = new java.util.ArrayDeque<>(java.util.List.of(secondSession));
        SseProxyServer proxy = new SseProxyServer(
                scannerSession, httpClient, firstSession, logging, sessions::poll);

        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.nextRequestId()).thenReturn(42L);
        when(scannerSession.refreshAuth()).thenReturn(true);

        ProxyResponse unauthorized = new ProxyResponse(401, "application/json", "{\"error\":\"invalid_token\"}");
        ProxyResponse success = new ProxyResponse(200, "application/json", "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        when(firstSession.forwardRequest(anyString(), anyMap())).thenReturn(unauthorized);
        when(secondSession.forwardRequest(anyString(), anyMap())).thenReturn(success);

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            verify(scannerSession, times(1)).refreshAuth();
            verify(firstSession, times(1)).forwardRequest(anyString(), anyMap());
            verify(firstSession, times(1)).close();
            verify(secondSession, times(1)).forwardRequest(anyString(), anyMap());
            ArgumentCaptor<String> outputMessage = ArgumentCaptor.forClass(String.class);
            verify(logging).logToOutput(outputMessage.capture());
            assertThat(outputMessage.getValue()).doesNotContain("OAuth");
            assertThat(eventLog.snapshot())
                    .anyMatch(entry -> entry.level() == McpEventLog.Level.INFO
                            && entry.message().contains("Authentication refresh after 401, retrying"));
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void serveSse_doesNotRetryOn401WhenAuthRefreshFails() throws Exception {
        SseScanSession sseScanSession = mock(SseScanSession.class);
        HttpClient httpClient = mock(HttpClient.class);
        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, sseScanSession, logging);

        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.nextRequestId()).thenReturn(42L);
        when(scannerSession.refreshAuth()).thenReturn(false);

        ProxyResponse unauthorized = new ProxyResponse(401, "application/json", "{\"error\":\"invalid_token\"}");
        when(sseScanSession.forwardRequest(anyString(), anyMap())).thenReturn(unauthorized);

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}"));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(401);
            verify(scannerSession, times(1)).refreshAuth();
            verify(sseScanSession, times(1)).forwardRequest(anyString(), anyMap());
            ArgumentCaptor<String> errorMessage = ArgumentCaptor.forClass(String.class);
            verify(logging).logToError(errorMessage.capture());
            assertThat(errorMessage.getValue()).doesNotContain("OAuth").startsWith("Auth refresh failed");
        } finally {
            proxy.stop();
        }
    }

    @Test
    void rejectsNonPostBeforeParsingBody() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
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

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
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
    @SuppressWarnings("unchecked")
    void acceptsExpectedEndpointPathFromRewrittenBurpRequest() throws Exception {
        String successBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json", successBody);
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/messages?session_id=abc");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        NanoHTTPD.IHTTPSession session = mockIHttpSession(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}",
                NanoHTTPD.Method.POST, "/messages", "session_id=abc");

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            assertThat(new String(response.getData().readAllBytes())).isEqualTo(successBody);
            verify(session).parseBody(any());
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
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("https://mcp.example.com");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        NanoHTTPD.IHTTPSession session = mockIHttpSession(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}",
                NanoHTTPD.Method.POST, "/", null);

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            assertThat(new String(response.getData().readAllBytes())).isEqualTo(successBody);
            verify(session).parseBody(any());
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
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://127.0.0.1:8000/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        NanoHTTPD.IHTTPSession session = mockIHttpSession(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}",
                NanoHTTPD.Method.POST, "/mcp", "");

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            assertThat(new String(response.getData().readAllBytes())).isEqualTo(successBody);
            verify(session).parseBody(any());
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
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://127.0.0.1:8000/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        NanoHTTPD.IHTTPSession session = mockIHttpSession(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\"}",
                NanoHTTPD.Method.POST, "/mcp", "x=1");

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            verify(session).parseBody(any());
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
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/messages?session_id=abc");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}", NanoHTTPD.Method.POST, "/messages",
                "session_id=other");

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            verify(session).parseBody(any());
        } finally {
            proxy.stop();
        }
    }

    @Test
    void rejectsDifferentPathBeforeForwarding() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/messages");

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
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

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
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
        SseProxyServer proxy = new SseProxyServer(scannerSession, logging);
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

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
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

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
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

    private static String sendRawHttp(int port, String request) throws Exception {
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.getOutputStream().write(request.getBytes(StandardCharsets.UTF_8));
            socket.getOutputStream().flush();
            return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardStreamableHttp_omitsAuthorizationWhenStripSentinelPresent() throws Exception {
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer session-token"));

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}",
                Map.of("X-Mcp-Scanner-Strip-Auth", "1"));

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertThat(captor.getValue().headers().firstValue("Authorization"))
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
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of(
                "Cookie", "session=abc",
                "X-Api-Key", "secret"));

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}",
                Map.of("X-Mcp-Scanner-Strip-Auth", "1"));

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            HttpRequest outbound = captor.getValue();
            assertThat(outbound.headers().firstValue("Cookie")).isEmpty();
            assertThat(outbound.headers().firstValue("X-Api-Key")).isEmpty();
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardStreamableHttp_dropsScannerProvidedAuthorizationSoFreshSessionTokenWins() throws Exception {
        // Authorization is reserved at the proxy boundary: any scanner-supplied Authorization
        // (typically a stale token baked into request bytes by JsonRpcRequestBuilder before a
        // mid-scan refresh) is dropped so the session's current token wins.
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer session-token"));

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}",
                Map.of("Authorization", "Bearer stale-baked-token"));

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertThat(captor.getValue().headers().firstValue("Authorization"))
                    .contains("Bearer session-token");
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
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}",
                Map.of("X-Mcp-Scanner-Strip-Auth", "1"));

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertThat(captor.getValue().headers().firstValue("X-Mcp-Scanner-Strip-Auth"))
                    .as("sentinel header must not leak to upstream MCP server")
                    .isEmpty();
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardStreamableHttp_injectsSessionAuthorizationByDefault() throws Exception {
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of("Authorization", "Bearer session-token"));

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}", Map.of());

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertThat(captor.getValue().headers().firstValue("Authorization"))
                    .contains("Bearer session-token");
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void forwardStreamableHttp_preservesScannerProvidedMcpSessionIdOverridingSession() throws Exception {
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of("Mcp-Session-Id", "session-stored"));

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}",
                Map.of("Mcp-Session-Id", "session-from-scanner"));

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertThat(captor.getValue().headers().firstValue("Mcp-Session-Id"))
                    .contains("session-from-scanner");
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void applyForwardHeaders_suppressesUnrecognizedSessionHeader_whenStripSentinelSet() throws Exception {
        // Locks the NON_AUTH_SESSION_HEADERS contract: any header name added to
        // scannerHeaders() that is NOT on the whitelist gets treated as auth-bearing and
        // suppressed by the strip-auth sentinel. If a future change adds a non-auth header
        // (e.g. tracing) to scannerHeaders() without updating NON_AUTH_SESSION_HEADERS, this
        // test fails to make the decision visible at code-review time.
        HttpResponse<InputStream> upstreamResponse = mockStreamResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of("X-Future-Tracing", "trace-abc"));

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}",
                Map.of("X-Mcp-Scanner-Strip-Auth", "1"));

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            assertThat(captor.getValue().headers().firstValue("X-Future-Tracing"))
                    .as("unrecognised scannerHeaders() entry must be treated as auth-bearing "
                            + "and suppressed when strip-auth sentinel is set — add the header to "
                            + "NON_AUTH_SESSION_HEADERS if it is genuinely non-auth")
                    .isEmpty();
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
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}", Map.of(
                "keep-alive", "timeout=5",
                "X-Custom", "keep-me"));

        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(session);

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            HttpRequest outbound = captor.getValue();
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
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(upstreamResponse);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        NanoHTTPD.IHTTPSession session = mockIHttpSession("{}", Map.of(
                "host", "fuzz.target.example",
                "content-length", "999",
                "connection", "keep-alive",
                "X-Custom", "keep-me"));

        proxy.start();
        try {
            proxy.serve(session);

            ArgumentCaptor<HttpRequest> captor = ArgumentCaptor.forClass(HttpRequest.class);
            verify(httpClient).send(captor.capture(), any(HttpResponse.BodyHandler.class));
            HttpRequest outbound = captor.getValue();
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
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        proxy.start();
        try {
            proxy.serve(mockIHttpSession("{}"));

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
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());

        SseProxyServer proxy = new SseProxyServer(scannerSession, httpClient, logging);
        proxy.start();
        try {
            NanoHTTPD.Response response = proxy.serve(mockIHttpSession("{}"));

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
        SseProxyServer proxy = new SseProxyServer(scannerSession, mock(HttpClient.class), logging);

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

    @SuppressWarnings("unchecked")
    private HttpResponse<InputStream> mockStreamResponse(int statusCode, String contentType, String body) {
        HttpResponse<InputStream> response = mock(HttpResponse.class);
        HttpHeaders headers = mock(HttpHeaders.class);
        lenient().when(headers.firstValue("Content-Type")).thenReturn(Optional.of(contentType));
        lenient().when(headers.allValues("Content-Type")).thenReturn(List.of(contentType));
        lenient().when(response.headers()).thenReturn(headers);
        lenient().when(response.statusCode()).thenReturn(statusCode);
        lenient().when(response.body()).thenReturn(new ByteArrayInputStream(body.getBytes()));
        return response;
    }
}
