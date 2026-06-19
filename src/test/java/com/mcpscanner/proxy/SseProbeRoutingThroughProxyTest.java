package com.mcpscanner.proxy;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.api.montoya.http.sessions.CookieJar;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.core.Registration;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.McpActiveResourcePathTraversalCheck;
import com.mcpscanner.checks.McpActiveUnauthenticatedToolDiscoveryCheck;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * End-to-end regression for the SSE self-issued-probe routing bug. {@code Http.sendRequest} bypasses
 * the registered {@code McpHttpHandler}, so before the fix a self-issued probe POSTed straight to the
 * upstream {@code /messages} endpoint — which on SSE answers with a bare {@code 202 Accepted} and an
 * EMPTY body (the JSON-RPC reply rides the {@code /sse} stream) — and the content oracle saw nothing.
 *
 * <p>Each test drives the real {@link SseProxyServer} reply-lifting (NOT the {@code RawSocketHttp}
 * double that pre-lifts the reply): the routing {@link Http} double dispatches by the request's
 * target {@link HttpService} — upstream gets the bare 202, the local proxy gets a real loopback HTTP
 * roundtrip whose response carries the JSON lifted by the {@link ReplyLifter} the test supplies. The
 * bug (and the test-confidence gap that hid it) is closed by asserting each probe NO-OPS when targeted
 * at the upstream and FIRES when routed through the proxy, across BOTH the hardcoded-payload path and
 * the DISCOVERY-driven path:
 *
 * <ul>
 *   <li>{@link #resourceTraversalProbe_fires_whenProbeRoutedThroughProxy()} — hardcoded absolute
 *       {@code file:///etc/passwd} payload (the original repro).</li>
 *   <li>{@link #discoveryDrivenResourceTraversalProbe_fires_whenProbeRoutedThroughProxy()} — the
 *       finding is driven by a URI the {@code resources/list} sub-request DISCOVERED, proving the
 *       discovery sub-request itself rides the proxy (not just the read probes).</li>
 *   <li>{@link #unauthenticatedToolDiscoveryProbe_fires_whenProbeRoutedThroughProxy()} — the
 *       {@code tools/list} discovery probe of {@link McpActiveUnauthenticatedToolDiscoveryCheck} on
 *       the no-auth branch.</li>
 * </ul>
 */
class SseProbeRoutingThroughProxyTest {

    private static final String UPSTREAM_HOST = "upstream.example";
    private static final int UPSTREAM_PORT = 9443;
    private static final String UPSTREAM_ENDPOINT =
            "http://" + UPSTREAM_HOST + ":" + UPSTREAM_PORT + "/messages?session_id=abc";

    private static final String PASSWD =
            "root:x:0:0:root:/root:/bin/bash\n"
                    + "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                    + "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n";

    /** A static resource the discovery sub-request advertises; its parent directory is the root the
     *  traversal then escapes out of, so the resulting probe URI is unique to the DISCOVERED URI. */
    private static final String DISCOVERED_RESOURCE_URI = "file:///srv/data/notes.txt";

    private static final String RESOURCES_READ_BASELINE_BODY =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"resources/read\",\"params\":{\"uri\":\"file:///x\"}}";
    private static final String TOOLS_LIST_BASELINE_BODY =
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}";

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    private SseProxyServer proxy;

    @AfterEach
    void stopProxy() {
        if (proxy != null) {
            proxy.stop();
        }
    }

    @Test
    void resourceTraversalProbe_noOps_whenProbeTargetsUpstreamBare202() throws Exception {
        startProxy(SseProbeRoutingThroughProxyTest::liftAbsolutePasswdReply);
        Http http = routingHttp();

        AuditResult result = resourceTraversalCheck(Optional::empty)
                .doCheck(baseline(RESOURCES_READ_BASELINE_BODY), insertionPoint(), http);

        assertThat(result.auditIssues())
                .as("pre-fix routing: probe hits the upstream /messages endpoint, reads a bare 202 "
                        + "empty body, and the oracle finds nothing")
                .isEmpty();
    }

    @Test
    void resourceTraversalProbe_fires_whenProbeRoutedThroughProxy() throws Exception {
        startProxy(SseProbeRoutingThroughProxyTest::liftAbsolutePasswdReply);
        Http http = routingHttp();

        AuditResult result = resourceTraversalCheck(this::proxyService)
                .doCheck(baseline(RESOURCES_READ_BASELINE_BODY), insertionPoint(), http);

        assertThat(result.auditIssues())
                .as("post-fix routing: probe targets the local proxy, which lifts the JSON-RPC reply "
                        + "off the /sse stream, so the file-read oracle fires")
                .isNotEmpty();
        assertThat(result.auditIssues().get(0).name()).contains("MCP Resource");
    }

    @Test
    void discoveryDrivenResourceTraversalProbe_noOps_whenProbeTargetsUpstreamBare202() throws Exception {
        startProxy(SseProbeRoutingThroughProxyTest::liftDiscoveryDrivenReply);
        Http http = routingHttp();

        AuditResult result = resourceTraversalCheck(Optional::empty)
                .doCheck(baseline(RESOURCES_READ_BASELINE_BODY), insertionPoint(), http);

        assertThat(result.auditIssues())
                .as("pre-fix routing: the resources/list discovery sub-request also hits the bare 202, "
                        + "so no resource URI is discovered and no discovery-driven probe is built")
                .isEmpty();
    }

    @Test
    void discoveryDrivenResourceTraversalProbe_fires_whenProbeRoutedThroughProxy() throws Exception {
        startProxy(SseProbeRoutingThroughProxyTest::liftDiscoveryDrivenReply);
        Http http = routingHttp();

        AuditResult result = resourceTraversalCheck(this::proxyService)
                .doCheck(baseline(RESOURCES_READ_BASELINE_BODY), insertionPoint(), http);

        // The lifter discloses passwd ONLY for a read escaping the DISCOVERED root (srv/data); the
        // hardcoded file:///etc/passwd payloads are answered with an error. So a finding can only come
        // from a URI the resources/list sub-request discovered — proving discovery rides the proxy.
        assertThat(result.auditIssues())
                .as("post-fix routing: the resources/list discovery sub-request rides the proxy, the "
                        + "discovered URI's escape reads out-of-root passwd, and the oracle fires")
                .isNotEmpty();
        assertThat(result.auditIssues().get(0).name()).contains("MCP Resource");
    }

    @Test
    void unauthenticatedToolDiscoveryProbe_noOps_whenProbeTargetsUpstreamBare202() throws Exception {
        startProxy(SseProbeRoutingThroughProxyTest::liftToolsListReply);
        Http http = routingHttp();

        AuditResult result = toolDiscoveryCheck(Optional::empty)
                .doCheck(baseline(TOOLS_LIST_BASELINE_BODY), insertionPoint(), http);

        assertThat(result.auditIssues())
                .as("pre-fix routing: the tools/list probe hits the bare 202 empty body, so "
                        + "isToolsListLeak is false and nothing fires")
                .isEmpty();
    }

    @Test
    void unauthenticatedToolDiscoveryProbe_fires_whenProbeRoutedThroughProxy() throws Exception {
        startProxy(SseProbeRoutingThroughProxyTest::liftToolsListReply);
        Http http = routingHttp();

        AuditResult result = toolDiscoveryCheck(this::proxyService)
                .doCheck(baseline(TOOLS_LIST_BASELINE_BODY), insertionPoint(), http);

        assertThat(result.auditIssues())
                .as("post-fix routing: the tools/list probe rides the proxy, which lifts a populated "
                        + "tool list off the /sse stream, so unauthenticated discovery fires")
                .isNotEmpty();
        assertThat(result.auditIssues().get(0).name()).contains("MCP Unauthenticated Tool Discovery");
    }

    private McpActiveResourcePathTraversalCheck resourceTraversalCheck(
            java.util.function.Supplier<Optional<HttpService>> probeService) {
        return new McpActiveResourcePathTraversalCheck(enabledSettings(), null,
                com.mcpscanner.scan.ScanInventory::empty, probeService);
    }

    private McpActiveUnauthenticatedToolDiscoveryCheck toolDiscoveryCheck(
            java.util.function.Supplier<Optional<HttpService>> probeService) {
        AuthStrategy noAuth = new NoAuthStrategy();
        return new McpActiveUnauthenticatedToolDiscoveryCheck(enabledSettings(), () -> noAuth, null,
                () -> TransportType.SSE, probeService);
    }

    private Optional<HttpService> proxyService() {
        return Optional.of(HttpService.httpService("127.0.0.1", proxy.port(), false));
    }

    /**
     * A reply lifter stands in for the {@code /sse}-owning {@link SseScanSession}: it correlates the
     * lifted JSON-RPC reply the proxy would pull off the stream for a given self-issued request body.
     */
    @FunctionalInterface
    private interface ReplyLifter extends Function<String, ProxyResponse> {}

    /** Absolute file:///etc/passwd discloses passwd; every other URI is an invalid-URI error. */
    private static ProxyResponse liftAbsolutePasswdReply(String requestBody) {
        if (requestBody.contains("file:///etc/passwd")) {
            return passwdReply();
        }
        return invalidUriError();
    }

    /**
     * Discovery-driven: resources/list advertises {@link #DISCOVERED_RESOURCE_URI}; a resources/read
     * that escapes out of that DISCOVERED root (srv/data) to etc/passwd discloses passwd. The
     * hardcoded absolute file:///etc/passwd payloads are rejected, so the only path to a finding is
     * via the discovered URI — proving the resources/list sub-request itself rode the proxy.
     */
    private static ProxyResponse liftDiscoveryDrivenReply(String requestBody) {
        if (requestBody.contains("resources/list")) {
            String json = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resources\":[{\"uri\":\""
                    + DISCOVERED_RESOURCE_URI + "\"}]}}";
            return new ProxyResponse(200, "application/json", json);
        }
        if (requestBody.contains("srv/data") && requestBody.contains("etc")
                && requestBody.contains("passwd")) {
            return passwdReply();
        }
        return invalidUriError();
    }

    /** tools/list returns a populated tool list; anything else is an invalid-URI error. */
    private static ProxyResponse liftToolsListReply(String requestBody) {
        if (requestBody.contains("tools/list")) {
            String json = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"echo\","
                    + "\"description\":\"echoes input\",\"inputSchema\":{\"type\":\"object\"}}]}}";
            return new ProxyResponse(200, "application/json", json);
        }
        return invalidUriError();
    }

    private static ProxyResponse passwdReply() {
        String json = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"contents\":[{\"text\":\""
                + PASSWD.replace("\n", "\\n") + "\"}]}}";
        return new ProxyResponse(200, "application/json", json);
    }

    private static ProxyResponse invalidUriError() {
        return new ProxyResponse(200, "application/json",
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32602,\"message\":\"Invalid URI\"}}");
    }

    private void startProxy(ReplyLifter lifter) throws IOException, InterruptedException {
        McpScannerSession session = mock(McpScannerSession.class);
        McpEventLog eventLog = new McpEventLog(null);
        lenient().when(session.eventLog()).thenReturn(eventLog);
        lenient().when(session.resolvedEndpoint()).thenReturn(UPSTREAM_ENDPOINT);
        lenient().when(session.transportType()).thenReturn(TransportType.SSE);
        lenient().when(session.nextRequestId()).thenReturn(1000L, 1001L, 1002L, 1003L, 1004L, 1005L);

        SseScanSession sseScanSession = mock(SseScanSession.class);
        lenient().when(sseScanSession.forwardRequest(anyString(), anyMap()))
                .thenAnswer(invocation -> lifter.apply(invocation.getArgument(0)));

        proxy = new SseProxyServer(session, mock(HttpClient.class), sseScanSession, mock(Logging.class));
        proxy.start();
    }

    private static ScanCheckSettings enabledSettings() {
        ScanCheckSettings settings = mock(ScanCheckSettings.class);
        lenient().when(settings.isEnabled(anyString(), anyBoolean())).thenReturn(true);
        return settings;
    }

    private static AuditInsertionPoint insertionPoint() {
        return mock(AuditInsertionPoint.class);
    }

    private HttpRequestResponse baseline(String body) {
        HttpRequest request = statefulRequest(body);
        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.request()).thenReturn(request);
        return rr;
    }

    /** Stateful request mock that tracks the body and service across withBody/withService/withHeader so
     *  the routing Http double can read the live target service the check selected. */
    private static HttpRequest statefulRequest(String body) {
        HttpService upstream = HttpService.httpService(UPSTREAM_HOST, UPSTREAM_PORT, false);
        return statefulRequestSharing(new AtomicReference<>(upstream), new AtomicReference<>(body));
    }

    private static HttpRequest statefulRequestSharing(AtomicReference<HttpService> serviceRef,
                                                      AtomicReference<String> bodyRef) {
        HttpRequest request = mock(HttpRequest.class);
        lenient().when(request.method()).thenReturn("POST");
        lenient().when(request.path()).thenReturn("/messages");
        lenient().when(request.bodyToString()).thenAnswer(inv -> bodyRef.get());
        lenient().when(request.httpService()).thenAnswer(inv -> serviceRef.get());
        lenient().when(request.headers()).thenReturn(List.of());
        lenient().when(request.withBody(anyString())).thenAnswer(inv ->
                statefulRequestSharing(serviceRef, new AtomicReference<>(inv.getArgument(0))));
        lenient().when(request.withService(any(HttpService.class)))
                .thenAnswer(inv -> {
                    serviceRef.set(inv.getArgument(0));
                    return request;
                });
        // Header mutations (the unauthenticated-discovery strip sentinel) must preserve the routed
        // service so the probe still targets the proxy after the auth headers are stripped.
        lenient().when(request.withHeader(anyString(), anyString()))
                .thenAnswer(inv -> statefulRequestSharing(serviceRef, bodyRef));
        lenient().when(request.withRemovedHeaders(
                        org.mockito.ArgumentMatchers.<List<? extends HttpHeader>>any()))
                .thenAnswer(inv -> statefulRequestSharing(serviceRef, bodyRef));
        return request;
    }

    /** Dispatches by the request's target service: the local proxy gets a real loopback HTTP
     *  roundtrip; the upstream gets the SSE-accurate bare 202 with an empty body. */
    private Http routingHttp() {
        return new RoutingHttp(proxy.port());
    }

    private static final class RoutingHttp implements Http {
        private final int proxyPort;

        RoutingHttp(int proxyPort) {
            this.proxyPort = proxyPort;
        }

        @Override
        public HttpRequestResponse sendRequest(HttpRequest request) {
            HttpService service = request.httpService();
            if ("127.0.0.1".equals(service.host()) && service.port() == proxyPort) {
                return sendToProxy(request);
            }
            return bare202(request);
        }

        private HttpRequestResponse sendToProxy(HttpRequest request) {
            try {
                String body = request.bodyToString();
                String wire = "POST /messages?session_id=abc HTTP/1.1\r\n"
                        + "Host: 127.0.0.1\r\n"
                        + "Content-Type: application/json\r\n"
                        + "Connection: close\r\n"
                        + "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n\r\n"
                        + body;
                String raw = roundtrip(wire);
                int headerEnd = raw.indexOf("\r\n\r\n");
                String headerBlock = headerEnd >= 0 ? raw.substring(0, headerEnd) : raw;
                String responseBody = headerEnd >= 0 ? raw.substring(headerEnd + 4) : "";
                String statusLine = headerBlock.split("\r\n", 2)[0];
                HttpResponse response = HttpResponse.httpResponse(
                        statusLine + "\r\nContent-Type: application/json\r\n\r\n" + responseBody);
                return HttpRequestResponse.httpRequestResponse(request, response);
            } catch (IOException e) {
                return HttpRequestResponse.httpRequestResponse(request, null);
            }
        }

        private String roundtrip(String wire) throws IOException {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("127.0.0.1", proxyPort), 5000);
                socket.setSoTimeout(5000);
                socket.getOutputStream().write(wire.getBytes(StandardCharsets.UTF_8));
                socket.getOutputStream().flush();
                return new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            }
        }

        private HttpRequestResponse bare202(HttpRequest request) {
            HttpResponse response = HttpResponse.httpResponse("HTTP/1.1 202 Accepted\r\n\r\n");
            return HttpRequestResponse.httpRequestResponse(request, response);
        }

        @Override public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode) { return sendRequest(request); }
        @Override public HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode, String connectionId) { return sendRequest(request); }
        @Override public HttpRequestResponse sendRequest(HttpRequest request, RequestOptions requestOptions) { return sendRequest(request); }
        @Override public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests) { return requests.stream().map(this::sendRequest).toList(); }
        @Override public List<HttpRequestResponse> sendRequests(List<HttpRequest> requests, HttpMode httpMode) { return sendRequests(requests); }
        @Override public Registration registerHttpHandler(HttpHandler handler) { throw new UnsupportedOperationException(); }
        @Override public Registration registerSessionHandlingAction(SessionHandlingAction sessionHandlingAction) { throw new UnsupportedOperationException(); }
        @Override public ResponseKeywordsAnalyzer createResponseKeywordsAnalyzer(List<String> keywords) { throw new UnsupportedOperationException(); }
        @Override public ResponseVariationsAnalyzer createResponseVariationsAnalyzer() { throw new UnsupportedOperationException(); }
        @Override public CookieJar cookieJar() { throw new UnsupportedOperationException(); }
    }
}
