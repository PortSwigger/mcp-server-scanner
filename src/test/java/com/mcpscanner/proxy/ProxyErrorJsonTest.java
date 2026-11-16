package com.mcpscanner.proxy;

import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.ProxyRequestStubs;
import fi.iki.elonen.NanoHTTPD;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ProxyErrorJsonTest {

    private static final String HOSTILE_MESSAGE = "upstream said \"no\" \\ then\nnewline";
    private static final String REQUEST = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";

    @Mock private McpScannerSession scannerSession;
    @Mock private Logging logging;

    @BeforeEach
    void stubEventLog() {
        lenient().when(scannerSession.eventLog()).thenReturn(new McpEventLog(logging));
    }

    @Test
    @SuppressWarnings("unchecked")
    void httpForwardFailureMessageIsEscapedIntoValidJson() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException(HOSTILE_MESSAGE));
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient).build();
        try {
            NanoHTTPD.Response response = proxy.serve(request("/mcp", ScannerSentinels.stripAuthOnly()));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(502);
            assertThat(errorField(response)).startsWith("Proxy error: ").contains(HOSTILE_MESSAGE);
        } finally {
            proxy.stop();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void noResponseThroughBurpFailuresAreReportedToTheConnectionLossWatch() throws Exception {
        HttpClient httpClient = mock(HttpClient.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("No response from http://127.0.0.1:8651/mcp through Burp: the connection"
                        + " or TLS handshake failed, or no complete reply arrived within 30 s"));
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        java.util.concurrent.atomic.AtomicInteger losses = new java.util.concurrent.atomic.AtomicInteger();
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).httpClient(httpClient)
                .connectionLossWatch(new com.mcpscanner.client.ConnectionLossWatch(2,
                        java.time.Duration.ofSeconds(60), java.time.Clock.systemUTC(),
                        () -> com.mcpscanner.client.PingOutcome.SESSION_REFUSED, 1, () -> { }, Runnable::run,
                        losses::incrementAndGet)).build();
        try {
            proxy.serve(request("/mcp", ScannerSentinels.stripAuthOnly()));
            assertThat(losses.get()).isZero();

            proxy.serve(request("/mcp", ScannerSentinels.stripAuthOnly()));

            assertThat(losses.get()).isEqualTo(1);
        } finally {
            proxy.stop();
        }
    }

    @Test
    void sseForwardFailureMessageIsEscapedIntoValidJson() throws Exception {
        SseScanSession managed = mock(SseScanSession.class);
        when(managed.forwardRequest(anyString(), anyMap())).thenThrow(new IOException(HOSTILE_MESSAGE));
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/sse");
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).managedSessions(managed).build();
        try {
            NanoHTTPD.Response response = proxy.serve(request("/sse", proxy.auditHeaders(Map.of())));

            assertThat(response.getStatus().getRequestStatus()).isEqualTo(502);
            assertThat(errorField(response)).isEqualTo("SSE proxy error: " + HOSTILE_MESSAGE);
        } finally {
            proxy.stop();
        }
    }

    @Test
    void rejectedRequestReasonIsValidJson() throws Exception {
        when(scannerSession.resolvedEndpoint()).thenReturn("http://upstream/mcp");
        SseProxyServer proxy = TestSseProxies.builder(scannerSession).build();
        NanoHTTPD.IHTTPSession get = request("/mcp", Map.of());
        when(get.getMethod()).thenReturn(NanoHTTPD.Method.GET);
        try {
            assertThat(errorField(proxy.serve(get))).isEqualTo("method GET not allowed");
        } finally {
            proxy.stop();
        }
    }

    private static NanoHTTPD.IHTTPSession request(String path, Map<String, String> headers) throws Exception {
        NanoHTTPD.IHTTPSession session = mock(NanoHTTPD.IHTTPSession.class);
        lenient().when(session.getMethod()).thenReturn(NanoHTTPD.Method.POST);
        lenient().when(session.getUri()).thenReturn(path);
        ProxyRequestStubs.stubBody(session, headers, REQUEST);
        return session;
    }

    private static String errorField(NanoHTTPD.Response response) throws IOException {
        String body = new String(response.getData().readAllBytes(), StandardCharsets.UTF_8);
        JsonNode json = McpObjectMapper.INSTANCE.readTree(body);
        return json.get("error").asText();
    }
}
