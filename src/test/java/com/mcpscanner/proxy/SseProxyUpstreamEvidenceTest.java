package com.mcpscanner.proxy;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.ProtocolHttpRequest;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.config.ClientIdentityProvider;
import com.mcpscanner.http.UpstreamEvidence;
import com.mcpscanner.http.WireResolvingCopies;
import com.mcpscanner.http.evidence.WireRecord;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.FakeMcpServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.ProxyRequestStubs;
import com.mcpscanner.testutil.ScriptedProtocolTransport;
import fi.iki.elonen.NanoHTTPD;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SseProxyUpstreamEvidenceTest {

    private static final String ENDPOINT = "https://upstream.test/mcp";
    private static final String TOOLS_CALL =
            "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{}}}";

    private final UpstreamRecording recording = UpstreamRecording.create();
    private McpScannerSession session;
    private SseProxyServer proxy;

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @AfterEach
    void tearDown() {
        if (proxy != null) proxy.stop();
        if (session != null) session.disconnect();
    }

    @Test
    void asPresentedForwardRecordsTheUpstreamExchangeWithoutSentinels() throws Exception {
        ScriptedProtocolTransport upstream = new ScriptedProtocolTransport(request -> FakeMcpServer.exchange(request,
                200, Map.of("Content-Type", List.of("text/event-stream"), "X-Upstream", List.of("modern")),
                "event: message\ndata: " + resultFor(request) + "\n\n"));
        proxy = proxyOver(TransportType.MODERN_HTTP, upstream);

        NanoHTTPD.Response response = proxy.serve(scannerRequest(Map.of(ScannerSentinels.STRIP_AUTH_HEADER, "1",
                "Authorization", "Bearer forged")));

        HttpRequestResponse evidence = evidenceFor(response);
        ProtocolHttpRequest sent = upstream.requests().get(0);
        assertThat(evidence.request().url()).isEqualTo(ENDPOINT);
        assertThat(evidence.request().headerValue("Authorization")).isEqualTo("Bearer forged");
        assertThat(evidence.request().headers()).noneMatch(header -> header.name().startsWith("X-Mcp-Scanner-"));
        assertThat(evidence.request().bodyToString()).isEqualTo(sent.body()).doesNotContain("\"id\":9,");
        assertThat(evidence.response().headerValue("X-Upstream")).isEqualTo("modern");
        assertThat(evidence.response().bodyToString()).isEqualTo("event: message\ndata: " + resultFor(sent) + "\n\n");
    }

    @Test
    void managedForwardRecordsTheRequestTheScannerSessionSentWithItsSessionHeaders() throws Exception {
        ScriptedProtocolTransport sessionUpstream = ScriptedProtocolTransport.fakeServer();
        proxy = proxies(TransportType.STREAMABLE_HTTP, sessionUpstream)
                .upstreamTransport(ScriptedProtocolTransport.fakeServer()).build();
        int sentBefore = sessionUpstream.requests().size();

        NanoHTTPD.Response response = proxy.serve(scannerRequest(proxy.auditHeaders(Map.of())));

        ProtocolHttpRequest sent = sessionUpstream.requests().get(sentBefore);
        HttpRequestResponse evidence = evidenceFor(response);
        assertThat(FakeMcpServer.method(sent)).isEqualTo("tools/call");
        assertThat(evidence.request().bodyToString()).isEqualTo(sent.body());
        assertThat(headerIgnoringCase(evidence.request(), "Mcp-Session-Id")).isEqualTo(FakeMcpServer.SESSION_ID);
        assertThat(evidence.response().bodyToString()).contains("\"result\"");
    }

    @Test
    void isolatedForwardRecordsTheScannerRequestNotItsHandshakeOrCleanup() throws Exception {
        ScriptedProtocolTransport upstream = new ScriptedProtocolTransport(request ->
                "initialize".equals(FakeMcpServer.method(request))
                        ? FakeMcpServer.exchange(request, 200, Map.of("Content-Type", List.of("application/json"),
                                "Mcp-Session-Id", List.of("isolated-session")), FakeMcpServer.initializeReply(request))
                        : FakeMcpServer.respond(request));
        proxy = proxyOver(TransportType.STREAMABLE_HTTP, upstream);
        int sentBefore = upstream.requests().size();

        NanoHTTPD.Response response = proxy.serve(scannerRequest(ScannerSentinels.stripAuthOnly()));

        assertThat(upstream.methods().subList(sentBefore, upstream.requests().size()))
                .containsExactly("initialize", "notifications/initialized", "tools/call", null);
        HttpRequestResponse evidence = evidenceFor(response);
        assertThat(evidence.request().method()).isEqualTo("POST");
        assertThat(evidence.request().bodyToString()).contains("\"tools/call\"");
        assertThat(headerIgnoringCase(evidence.request(), "Mcp-Session-Id")).isEqualTo("isolated-session");
    }

    @Test
    void asPresentedForwardNeitherSendsNorRecordsTheLocalServersClientAddressHeaders() throws Exception {
        ScriptedProtocolTransport upstream = new ScriptedProtocolTransport(FakeMcpServer::respond);
        proxy = proxyOver(TransportType.MODERN_HTTP, upstream);

        NanoHTTPD.Response response = proxy.serve(scannerRequest(withClientAddress(ScannerSentinels.stripAuthOnly())));

        assertCarriesNoClientAddress(upstream.requests().get(0).headers().keySet());
        assertThat(itemsFor(response)).isNotEmpty()
                .allSatisfy(item -> assertCarriesNoClientAddress(headerNames(item.request())));
    }

    @Test
    void managedForwardNeitherSendsNorRecordsTheLocalServersClientAddressHeaders() throws Exception {
        ScriptedProtocolTransport sessionUpstream = ScriptedProtocolTransport.fakeServer();
        proxy = proxies(TransportType.STREAMABLE_HTTP, sessionUpstream)
                .upstreamTransport(ScriptedProtocolTransport.fakeServer()).build();
        int sentBefore = sessionUpstream.requests().size();

        NanoHTTPD.Response response = proxy.serve(scannerRequest(withClientAddress(proxy.auditHeaders(Map.of()))));

        assertCarriesNoClientAddress(sessionUpstream.requests().get(sentBefore).headers().keySet());
        assertThat(itemsFor(response)).isNotEmpty()
                .allSatisfy(item -> assertCarriesNoClientAddress(headerNames(item.request())));
    }

    @Test
    void isolatedForwardNeitherSendsNorRecordsTheLocalServersClientAddressHeaders() throws Exception {
        ScriptedProtocolTransport upstream = new ScriptedProtocolTransport(request ->
                "initialize".equals(FakeMcpServer.method(request))
                        ? FakeMcpServer.exchange(request, 200, Map.of("Content-Type", List.of("application/json"),
                                "Mcp-Session-Id", List.of("isolated-session")), FakeMcpServer.initializeReply(request))
                        : FakeMcpServer.respond(request));
        proxy = proxyOver(TransportType.STREAMABLE_HTTP, upstream);

        NanoHTTPD.Response response = proxy.serve(scannerRequest(withClientAddress(ScannerSentinels.stripAuthOnly())));

        upstream.requests().forEach(sent -> assertCarriesNoClientAddress(sent.headers().keySet()));
        assertThat(itemsFor(response)).isNotEmpty()
                .allSatisfy(item -> assertCarriesNoClientAddress(headerNames(item.request())));
    }

    @Test
    void sseForwardNeitherSendsNorRecordsTheLocalServersClientAddressHeaders() throws Exception {
        proxy = sseProxy(new SseUpstream(202));

        NanoHTTPD.Response response = proxy.serve(requestTo("/message",
                withClientAddress(ScannerSentinels.stripAuthOnly())));

        assertThat(itemsFor(response)).isNotEmpty()
                .allSatisfy(item -> assertCarriesNoClientAddress(headerNames(item.request())));
    }

    @Test
    void upstreamTransportFailureIsAFabricatedReplyWithoutAnExchangeHeader() throws Exception {
        ScriptedProtocolTransport upstream = new ScriptedProtocolTransport(request -> {
            throw new ScriptedProtocolTransport.ScriptedIoFailure(new IOException("connection reset"));
        });
        proxy = proxies(TransportType.MODERN_HTTP, ScriptedProtocolTransport.fakeServer()).upstreamTransport(upstream)
                .build();

        NanoHTTPD.Response response = proxy.serve(scannerRequest(ScannerSentinels.stripAuthOnly()));

        assertThat(response.getStatus().getRequestStatus()).isEqualTo(502);
        assertThat(response.getHeader(ScannerSentinels.EXCHANGE_HEADER)).isNull();
    }

    @Test
    void oversizedScannerBodyIsAFabricatedReplyWithoutAnExchangeHeader() throws Exception {
        proxy = proxies(TransportType.MODERN_HTTP, ScriptedProtocolTransport.fakeServer()).postBodyLimit(8).build();

        NanoHTTPD.Response response = proxy.serve(scannerRequest(ScannerSentinels.stripAuthOnly()));

        assertThat(response.getStatus().getRequestStatus()).isEqualTo(413);
        assertThat(response.getHeader(ScannerSentinels.EXCHANGE_HEADER)).isNull();
    }

    @Test
    void sseForwardRecordsThePostWithItsOwnReplyThenTheStreamsGetWithTheRawEventThatAnsweredIt() throws Exception {
        SseUpstream upstream = new SseUpstream(202);
        proxy = sseProxy(upstream);

        NanoHTTPD.Response response = proxy.serve(sseScannerRequest());

        List<HttpRequestResponse> evidence = itemsFor(response);
        assertThat(evidence).hasSize(2);
        HttpRequestResponse post = evidence.get(0);
        String sentBody = post.request().bodyToString();
        assertThat(text(post.request().toByteArray())).startsWith("POST /message?session=isolated HTTP/1.1\r\n")
                .contains("Host: upstream\r\n", "Content-Length: " + sentBody.length() + "\r\n",
                        "User-Agent: Java-http-client/", "Content-Type: application/json\r\n")
                .doesNotContainIgnoringCase("X-Mcp-Scanner-");
        assertThat(sentBody).contains("\"tools/call\"").doesNotContain("\"id\":9,");
        assertThat(post.response().statusCode()).isEqualTo((short) 202);
        assertThat(post.response().body().length()).isZero();
        assertStreamEvent(evidence.get(1), upstream);
    }

    @Test
    void aLaunchedBaseKeepsItsStreamEvidenceAfterLaterProbesOverflowTheStore() throws Exception {
        SseUpstream upstream = new SseUpstream(202);
        proxy = sseProxy(upstream);
        recording.launchedBases().remember(TOOLS_CALL);

        NanoHTTPD.Response response = proxy.serve(sseScannerRequest());
        overflowTheStoreWithProbes();

        List<HttpRequestResponse> evidence = itemsFor(response);
        assertThat(evidence).hasSize(2);
        assertThat(evidence.get(0).response().statusCode()).isEqualTo((short) 202);
        assertStreamEvent(evidence.get(1), upstream);
    }

    @Test
    void aProbeKeptForALateIssueStillResolvesToBothItemsAfterTheStoreEvictedIt() throws Exception {
        SseUpstream upstream = new SseUpstream(202);
        proxy = sseProxy(upstream);
        NanoHTTPD.Response response = proxy.serve(sseScannerRequest());
        HttpRequestResponse kept = new WireResolvingCopies(exchange -> exchange, recording.store())
                .kept(proxiedCarrying(response));

        overflowTheStoreWithProbes();

        List<HttpRequestResponse> evidence = new UpstreamEvidence(recording.store()).resolved(kept);
        assertThat(evidence).hasSize(2);
        assertThat(evidence.get(0).response().statusCode()).isEqualTo((short) 202);
        assertStreamEvent(evidence.get(1), upstream);
    }

    private static void assertStreamEvent(HttpRequestResponse event, SseUpstream upstream) {
        assertThat(text(event.request().toByteArray())).startsWith("GET /sse HTTP/1.1\r\n")
                .doesNotContainIgnoringCase("X-Mcp-Scanner-");
        assertThat(text(event.response().toByteArray())).isEqualTo(SseUpstream.STREAM_HEAD + upstream.rawToolCallReply());
    }

    @Test
    void aProbeResendingTheLaunchedBodyUnchangedIsNotKeptInPlaceOfTheBase() throws Exception {
        recording.launchedBases().remember(TOOLS_CALL);
        SseProxyServer baseProxy = sseProxy(new SseUpstream(202));
        try {
            baseProxy.serve(sseScannerRequest());
        } finally {
            baseProxy.stop();
        }
        proxy = sseProxy(new SseUpstream(202));

        NanoHTTPD.Response resent = proxy.serve(sseScannerRequest());
        overflowTheStoreWithProbes();

        assertThat(recording.store().upstreamOf(proxiedCarrying(resent))).isEmpty();
    }

    @Test
    void aProbeThatWasNotLaunchedAsABaseIsEvictedOnceLaterProbesOverflowTheStore() throws Exception {
        proxy = sseProxy(new SseUpstream(202));

        NanoHTTPD.Response response = proxy.serve(sseScannerRequest());
        overflowTheStoreWithProbes();

        assertThat(recording.store().upstreamOf(proxiedCarrying(response))).isEmpty();
    }

    @Test
    void sseRefusedPostRecordsTheBodyBytesAsReceivedWithEachHeaderValueOnItsOwnLine() throws Exception {
        SseUpstream upstream = new SseUpstream(403);
        proxy = sseProxy(upstream);

        NanoHTTPD.Response response = proxy.serve(sseScannerRequest());

        HttpRequestResponse evidence = evidenceFor(response);
        assertThat(evidence.response().statusCode()).isEqualTo((short) 403);
        assertThat(text(evidence.response().toByteArray())).contains("Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n");
        assertThat(evidence.response().body().getBytes()).isEqualTo(SseUpstream.REFUSAL);
    }

    @Test
    void asPresentedReplyRelaysTheUpstreamStatusAndHeadersWithoutFramingOrSession() throws Exception {
        ScriptedProtocolTransport upstream = new ScriptedProtocolTransport(request -> FakeMcpServer.exchange(request,
                207, upstreamHeaders("text/event-stream", "modern"), "event: message\ndata: " + resultFor(request) + "\n\n"));
        proxy = proxyOver(TransportType.MODERN_HTTP, upstream);

        NanoHTTPD.Response response = proxy.serve(scannerRequest(ScannerSentinels.stripAuthOnly()));

        assertThat(response.getStatus().getRequestStatus()).isEqualTo(207);
        assertThat(response.getMimeType()).isEqualTo("application/json");
        assertRelaysOnlyEndToEndHeaders(response, "modern");
    }

    @Test
    void managedReplyRelaysTheUpstreamHeadersWithoutFramingOrSession() throws Exception {
        ScriptedProtocolTransport sessionUpstream = new ScriptedProtocolTransport(request ->
                "tools/call".equals(FakeMcpServer.method(request))
                        ? FakeMcpServer.exchange(request, 200, upstreamHeaders("application/json", "managed"),
                                resultFor(request))
                        : FakeMcpServer.respond(request));
        proxy = proxies(TransportType.STREAMABLE_HTTP, sessionUpstream)
                .upstreamTransport(ScriptedProtocolTransport.fakeServer()).build();

        NanoHTTPD.Response response = proxy.serve(scannerRequest(proxy.auditHeaders(Map.of())));

        assertThat(response.getMimeType()).isEqualTo("application/json");
        assertRelaysOnlyEndToEndHeaders(response, "managed");
    }

    @Test
    void isolatedReplyRelaysTheUpstreamHeadersWithoutFramingOrSession() throws Exception {
        ScriptedProtocolTransport upstream = new ScriptedProtocolTransport(request ->
                "initialize".equals(FakeMcpServer.method(request))
                        ? FakeMcpServer.exchange(request, 200, Map.of("Content-Type", List.of("application/json"),
                                "Mcp-Session-Id", List.of("isolated-session")), FakeMcpServer.initializeReply(request))
                        : "tools/call".equals(FakeMcpServer.method(request))
                                ? FakeMcpServer.exchange(request, 200, upstreamHeaders("application/json", "isolated"),
                                        resultFor(request))
                                : FakeMcpServer.respond(request));
        proxy = proxyOver(TransportType.STREAMABLE_HTTP, upstream);

        NanoHTTPD.Response response = proxy.serve(scannerRequest(ScannerSentinels.stripAuthOnly()));

        assertRelaysOnlyEndToEndHeaders(response, "isolated");
    }

    @Test
    void sseReplyRelaysThePostHeadersBesideTheStreamReply() throws Exception {
        proxy = sseProxy(new SseUpstream(202));

        NanoHTTPD.Response response = proxy.serve(sseScannerRequest());

        assertThat(response.getStatus().getRequestStatus()).isEqualTo(200);
        assertThat(response.getHeader("X-Upstream")).isEqualTo("sse");
        assertThat(response.getHeader("Content-Length")).isNull();
    }

    @Test
    void sseRefusedPostRelaysItsStatusAndHeaders() throws Exception {
        proxy = sseProxy(new SseUpstream(403));

        NanoHTTPD.Response response = proxy.serve(sseScannerRequest());

        assertThat(response.getStatus().getRequestStatus()).isEqualTo(403);
        assertThat(response.getHeader("X-Upstream")).isEqualTo("sse");
    }

    private static Map<String, String> withClientAddress(Map<String, String> headers) {
        Map<String, String> received = new HashMap<>(headers);
        received.put("remote-addr", "127.0.0.1");
        received.put("http-client-ip", "127.0.0.1");
        return received;
    }

    private static List<String> headerNames(HttpRequest request) {
        return request.headers().stream().map(burp.api.montoya.http.message.HttpHeader::name).toList();
    }

    private static void assertCarriesNoClientAddress(java.util.Collection<String> headerNames) {
        assertThat(headerNames).noneMatch(name -> name.equalsIgnoreCase("remote-addr")
                || name.equalsIgnoreCase("http-client-ip"));
    }

    private static Map<String, List<String>> upstreamHeaders(String contentType, String marker) {
        return Map.of("Content-Type", List.of(contentType), "X-Upstream", List.of(marker),
                "Content-Length", List.of("999"), "Transfer-Encoding", List.of("chunked"),
                "Connection", List.of("close"), "Keep-Alive", List.of("timeout=5"),
                "Mcp-Session-Id", List.of("upstream-session"));
    }

    private static void assertRelaysOnlyEndToEndHeaders(NanoHTTPD.Response response, String marker) {
        assertThat(response.getHeader("X-Upstream")).isEqualTo(marker);
        assertThat(response.getHeader(ScannerSentinels.EXCHANGE_HEADER)).isNotNull();
        List.of("Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive", "Mcp-Session-Id", "Content-Type")
                .forEach(name -> assertThat(response.getHeader(name)).as(name).isNull());
    }

    private HttpRequestResponse evidenceFor(NanoHTTPD.Response response) {
        List<HttpRequestResponse> items = itemsFor(response);
        assertThat(items).hasSize(1);
        return items.get(0);
    }

    private List<HttpRequestResponse> itemsFor(NanoHTTPD.Response response) {
        return recording.store().upstreamOf(proxiedCarrying(response));
    }

    private static HttpRequestResponse proxiedCarrying(NanoHTTPD.Response response) {
        String id = response.getHeader(ScannerSentinels.EXCHANGE_HEADER);
        assertThat(id).isNotNull();
        return HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl("http://127.0.0.1:1/mcp"),
                HttpResponse.httpResponse("HTTP/1.1 200\r\n" + ScannerSentinels.EXCHANGE_HEADER + ": " + id
                        + "\r\n\r\n{}"));
    }

    private void overflowTheStoreWithProbes() {
        RecordedExchange probe = new RecordedExchange("{}", WireRecord.ofBurp(HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequestFromUrl("http://upstream/message"),
                HttpResponse.httpResponse("HTTP/1.1 202 Accepted\r\n\r\n"))));
        java.util.stream.IntStream.range(0, UpstreamExchangeStore.MAX_EXCHANGES)
                .forEach(index -> recording.store().put(probe));
    }

    private SseProxyServer proxyOver(TransportType transport, ScriptedProtocolTransport upstream) {
        return proxies(transport, ScriptedProtocolTransport.fakeServer()).upstreamTransport(upstream).build();
    }

    private static String headerIgnoringCase(HttpRequest request, String name) {
        return request.headers().stream().filter(header -> header.name().equalsIgnoreCase(name))
                .map(burp.api.montoya.http.message.HttpHeader::value).findFirst().orElse(null);
    }

    private TestSseProxies.Builder proxies(TransportType transport, ScriptedProtocolTransport sessionUpstream) {
        session = new McpScannerSession(mock(HttpClient.class), recording.captures().recording(sessionUpstream),
                McpEventLog.noop(), () -> true, ClientIdentityProvider.defaults());
        session.connect(new McpServerConfig(ENDPOINT, transport, new NoAuthStrategy()));
        return TestSseProxies.builder(session).httpClient(mock(HttpClient.class)).recording(recording);
    }

    private SseProxyServer sseProxy(SseUpstream upstream) throws Exception {
        McpScannerSession sseSession = mock(McpScannerSession.class);
        lenient().when(sseSession.eventLog()).thenReturn(McpEventLog.noop());
        when(sseSession.resolvedEndpoint()).thenReturn("http://upstream/message");
        when(sseSession.sseUrl()).thenReturn("http://upstream/sse");
        when(sseSession.transportType()).thenReturn(TransportType.SSE);
        AtomicLong ids = new AtomicLong(100);
        when(sseSession.nextRequestId()).thenAnswer(invocation -> ids.getAndIncrement());
        return TestSseProxies.builder(sseSession).httpClient(upstream.client()).recording(recording).build();
    }

    private static String resultFor(ProtocolHttpRequest request) {
        return "{\"jsonrpc\":\"2.0\",\"id\":" + idOf(request.body()) + ",\"result\":{\"content\":[]}}";
    }

    private static String idOf(String body) {
        try {
            return McpObjectMapper.INSTANCE.readTree(body).path("id").toString();
        } catch (IOException invalid) {
            throw new IllegalStateException(invalid);
        }
    }

    private static NanoHTTPD.IHTTPSession scannerRequest(Map<String, String> headers) {
        return requestTo("/mcp", headers);
    }

    private static NanoHTTPD.IHTTPSession sseScannerRequest() {
        return requestTo("/message", new HashMap<>(ScannerSentinels.stripAuthOnly()));
    }

    private static NanoHTTPD.IHTTPSession requestTo(String path, Map<String, String> headers) {
        NanoHTTPD.IHTTPSession request = mock(NanoHTTPD.IHTTPSession.class);
        when(request.getMethod()).thenReturn(NanoHTTPD.Method.POST);
        when(request.getUri()).thenReturn(path);
        ProxyRequestStubs.stubBody(request, headers, TOOLS_CALL);
        return request;
    }

    private static final class SseUpstream {

        static final String STREAM_HEAD = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                + "X-Stream: one\r\nX-Stream: two\r\n\r\n";
        static final byte[] REFUSAL = {'{', '"', 'e', '"', ':', '"', (byte) 0xff, '"', '}'};

        private final int toolCallStatus;
        private final SseScanSessionTest.QueueInputStream stream = new SseScanSessionTest.QueueInputStream();
        private volatile String rawToolCallReply;

        private SseUpstream(int toolCallStatus) {
            this.toolCallStatus = toolCallStatus;
            stream.push("event: endpoint\ndata: /message?session=isolated\n\n");
        }

        String rawToolCallReply() {
            return rawToolCallReply;
        }

        @SuppressWarnings("unchecked")
        HttpClient client() throws Exception {
            HttpClient client = mock(HttpClient.class);
            java.net.http.HttpResponse<InputStream> opened = mock(java.net.http.HttpResponse.class);
            AtomicReference<java.net.http.HttpRequest> openedWith = new AtomicReference<>();
            lenient().when(opened.request()).thenAnswer(invocation -> openedWith.get());
            lenient().when(opened.statusCode()).thenReturn(200);
            lenient().when(opened.body()).thenReturn(stream);
            lenient().when(opened.headers()).thenReturn(headers(Map.of("Content-Type",
                    List.of("text/event-stream"), "X-Stream", List.of("one", "two"))));
            when(client.send(any(java.net.http.HttpRequest.class), any(java.net.http.HttpResponse.BodyHandler.class)))
                    .thenAnswer(invocation -> {
                        java.net.http.HttpRequest request = invocation.getArgument(0);
                        if (request.method().equals("GET")) {
                            openedWith.set(request);
                            return opened;
                        }
                        return posted(SseProxyServerTest.extractBody(request), invocation.getArgument(1));
                    });
            return client;
        }

        @SuppressWarnings("unchecked")
        private java.net.http.HttpResponse<String> posted(String body,
                                                          java.net.http.HttpResponse.BodyHandler<String> handler)
                throws IOException {
            JsonNode message = McpObjectMapper.INSTANCE.readTree(body);
            boolean toolCall = "tools/call".equals(message.path("method").asText());
            int status = toolCall ? toolCallStatus : 202;
            if (status == 202 && message.has("id")) {
                stream.push(toolCall ? rawToolCallReplyTo(message) : "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":"
                        + message.get("id") + ",\"result\":{}}\n\n");
            }
            java.net.http.HttpResponse<String> response = mock(java.net.http.HttpResponse.class);
            lenient().when(response.statusCode()).thenReturn(status);
            lenient().when(response.headers()).thenReturn(headers(Map.of("X-Upstream", List.of("sse"),
                    "Set-Cookie", List.of("a=1", "b=2"))));
            String received = receive(handler, status == 202 ? new byte[0] : REFUSAL);
            lenient().when(response.body()).thenReturn(received);
            return response;
        }

        private String rawToolCallReplyTo(JsonNode message) {
            rawToolCallReply = "id: 77\r\nevent: message\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":" + message.get("id")
                    + ",\r\ndata: \"result\":{}}\r\n\r\n";
            return rawToolCallReply;
        }

        private static String receive(java.net.http.HttpResponse.BodyHandler<String> handler, byte[] body) {
            java.net.http.HttpResponse.BodySubscriber<String> subscriber = handler.apply(null);
            subscriber.onSubscribe(new java.util.concurrent.Flow.Subscription() {
                @Override
                public void request(long n) {
                }

                @Override
                public void cancel() {
                }
            });
            if (body.length > 0) {
                subscriber.onNext(List.of(java.nio.ByteBuffer.wrap(body)));
            }
            subscriber.onComplete();
            return subscriber.getBody().toCompletableFuture().join();
        }

        private static HttpHeaders headers(Map<String, List<String>> values) {
            return HttpHeaders.of(values, (name, value) -> true);
        }
    }

    private static String text(burp.api.montoya.core.ByteArray bytes) {
        return new String(bytes.getBytes(), java.nio.charset.StandardCharsets.ISO_8859_1);
    }
}
