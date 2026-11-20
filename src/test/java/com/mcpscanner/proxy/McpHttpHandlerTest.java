package com.mcpscanner.proxy;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestAction;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.SpoofedRequestAction;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class McpHttpHandlerTest {

    @Mock private McpScannerSession scannerSession;
    @Mock private SseProxyServer proxy;
    @Mock private HttpRequestToBeSent request;
    @Mock private HttpService httpService;
    @Mock private HttpRequest rewrittenRequest;
    @Mock private HttpResponseReceived response;
    @Mock private Annotations annotations;
    @Mock private Http1LoopbackRelay relay;
    @Mock private HttpResponse loopbackResponse;
    @Mock private HttpRequest keyedRequest;
    @Mock private burp.api.montoya.core.ToolSource toolSource;

    private final LoopbackRoutingKey routingKey = LoopbackRoutingKey.mint();

    private McpHttpHandler handler;

    @BeforeAll
    static void installFactory() {
        MontoyaTestFactory.install();
    }

    @BeforeEach
    void setUp() {
        handler = new McpHttpHandler(scannerSession, proxy, relay);
        when(proxy.routingKey()).thenReturn(routingKey);
        when(request.withHeader(ScannerSentinels.ROUTED_HEADER, routingKey.value())).thenReturn(request);
    }

    @Test
    void serviceSwappedRequestCarriesTheProxyRoutingKey() {
        stubSseEndpoint();
        when(request.withHeader(ScannerSentinels.ROUTED_HEADER, routingKey.value())).thenReturn(keyedRequest);
        when(keyedRequest.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(rewrittenRequest);
    }

    @Test
    void relayedRequestCarriesTheProxyRoutingKey() {
        stubSseEndpoint();
        when(request.withHeader(ScannerSentinels.ROUTED_HEADER, routingKey.value())).thenReturn(keyedRequest);
        when(relay.needsRelay(request)).thenReturn(true);
        when(relay.relay(org.mockito.ArgumentMatchers.eq(keyedRequest), proxyService()))
                .thenReturn(java.util.Optional.of(loopbackResponse));

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(((SpoofedRequestAction) result).response()).isSameAs(loopbackResponse);
    }

    @Test
    void harnessRoutedRequestCarriesTheProxyRoutingKey() {
        stubSseEndpoint();
        when(request.withHeader(ScannerSentinels.ROUTED_HEADER, routingKey.value())).thenReturn(keyedRequest);
        when(keyedRequest.withService(proxyService())).thenReturn(rewrittenRequest);

        assertThat(handler.route(request)).isSameAs(rewrittenRequest);
    }

    @Test
    void directDeliveryRequestDoesNotCarryTheRoutingKey() {
        stubSseEndpoint();
        when(request.hasHeader(ScannerSentinels.DIRECT_DELIVERY_HEADER)).thenReturn(true);
        when(request.withRemovedHeader(anyString())).thenReturn(request);

        handler.handleHttpRequestToBeSent(request);
        handler.route(request);

        verify(request, never()).withHeader(ScannerSentinels.ROUTED_HEADER, routingKey.value());
    }

    @Test
    void requestNotBoundForTheProxyDoesNotCarryTheRoutingKey() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:3001/mcp");
        when(proxy.port()).thenReturn(9999);
        stubRequest("localhost", 3001, "/other");

        handler.handleHttpRequestToBeSent(request);
        handler.route(request);

        verify(request, never()).withHeader(ScannerSentinels.ROUTED_HEADER, routingKey.value());
    }

    @Test
    void scannerRequestAlreadyAddressedToTheProxyCarriesTheRoutingKey() {
        stubSseEndpoint();
        stubRequest("127.0.0.1", 9999, "/mcp");
        when(toolSource.isFromTool(burp.api.montoya.core.ToolType.SCANNER)).thenReturn(true);
        when(request.withHeader(ScannerSentinels.ROUTED_HEADER, routingKey.value())).thenReturn(keyedRequest);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(keyedRequest);
    }

    @Test
    void extensionRequestAlreadyAddressedToTheProxyCarriesTheRoutingKey() {
        stubSseEndpoint();
        stubRequest("127.0.0.1", 9999, "/mcp");
        when(toolSource.isFromTool(burp.api.montoya.core.ToolType.EXTENSIONS)).thenReturn(true);
        when(request.withHeader(ScannerSentinels.ROUTED_HEADER, routingKey.value())).thenReturn(keyedRequest);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(keyedRequest);
    }

    @Test
    void proxyToolRequestAddressedToTheProxyDoesNotCarryTheRoutingKey() {
        stubSseEndpoint();
        stubRequest("127.0.0.1", 9999, "/mcp");
        when(toolSource.isFromTool(burp.api.montoya.core.ToolType.PROXY)).thenReturn(true);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(request);
        verify(request, never()).withHeader(ScannerSentinels.ROUTED_HEADER, routingKey.value());
    }

    @Test
    void requestToAnotherHostDoesNotCarryTheRoutingKey() {
        stubSseEndpoint();
        stubRequest("elsewhere.example", 3001, "/mcp");
        when(toolSource.isFromTool(burp.api.montoya.core.ToolType.SCANNER)).thenReturn(true);

        handler.handleHttpRequestToBeSent(request);

        verify(request, never()).withHeader(ScannerSentinels.ROUTED_HEADER, routingKey.value());
    }

    private void stubSseEndpoint() {
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:3001/mcp");
        when(proxy.port()).thenReturn(9999);
        stubRequest("localhost", 3001, "/mcp");
    }

    @Test
    void rewritesStreamableHttpJsonRpcRequestToProxy() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:3001/mcp");
        when(proxy.port()).thenReturn(9999);
        stubRequest("localhost", 3001, "/mcp");
        when(request.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(rewrittenRequest);
        verify(request).withService(any(HttpService.class));
    }

    @Test
    void stripsAuditCapabilityWhenScannerChangesPathAndBypassesProxy() {
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.resolvedEndpoint()).thenReturn("https://upstream/mcp");
        stubRequest("upstream", 443, "/mcp/backup");
        var marker = org.mockito.Mockito.mock(burp.api.montoya.http.message.HttpHeader.class);
        when(marker.name()).thenReturn(ScannerSentinels.AUDIT_CAPABILITY_HEADER);
        when(request.headers()).thenReturn(java.util.List.of(marker));
        when(request.withRemovedHeaders(java.util.List.of(marker))).thenReturn(rewrittenRequest);

        var action = handler.handleHttpRequestToBeSent(request);

        assertThat(action.request()).isSameAs(rewrittenRequest);
        verify(request).withRemovedHeaders(java.util.List.of(marker));
    }

    @Test
    void stripsEveryUpstreamOnlySentinelWhenARequestBypassesTheProxy() {
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.resolvedEndpoint()).thenReturn("https://upstream/mcp");
        stubRequest("upstream", 443, "/mcp/backup");
        var capability = header(ScannerSentinels.AUDIT_CAPABILITY_HEADER);
        var framed = header(ScannerSentinels.FRAMED_OPERATION_HEADER);
        var stripAuth = header(ScannerSentinels.STRIP_AUTH_HEADER);
        var custom = header("X-Custom");
        when(request.headers()).thenReturn(java.util.List.of(capability, framed, stripAuth, custom));
        when(request.withRemovedHeaders(java.util.List.of(capability, framed, stripAuth))).thenReturn(rewrittenRequest);

        var action = handler.handleHttpRequestToBeSent(request);

        assertThat(action.request()).isSameAs(rewrittenRequest);
    }

    private static burp.api.montoya.http.message.HttpHeader header(String name) {
        var header = org.mockito.Mockito.mock(burp.api.montoya.http.message.HttpHeader.class);
        when(header.name()).thenReturn(name);
        return header;
    }

    @Test
    void rewritesSseTransportRequestsToProxy() {
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:3001/message");
        when(proxy.port()).thenReturn(9999);
        stubRequest("localhost", 3001, "/message");
        when(request.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(rewrittenRequest);
        verify(request).withService(any(HttpService.class));
    }

    @Test
    void rewritesHttpsRequestWithDefaultPortToProxy() {
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.resolvedEndpoint()).thenReturn("https://example.com/messages?session_id=abc");
        when(proxy.port()).thenReturn(9999);
        stubRequest("example.com", 443, "/messages");
        when(request.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(rewrittenRequest);
        verify(request).withService(any(HttpService.class));
    }

    @Test
    void stampsOriginalHostInAnnotationsNotesWhenRewriting() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("https://mcp.example.com/v1/mcp");
        when(proxy.port()).thenReturn(9999);
        stubRequest("mcp.example.com", 443, "/v1/mcp");
        when(request.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        handler.handleHttpRequestToBeSent(request);

        verify(annotations).setNotes("→ mcp.example.com");
    }

    /**
     * Method-irrelevance regression: the handler must rewrite the MCP endpoint path regardless of
     * method (POST / GET / OPTIONS / HEAD). Only the path component participates in the match.
     */
    @Test
    void rewritesEvenIfMethodIsNotPost_whenPathMatchesEndpoint() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:3001/mcp");
        when(proxy.port()).thenReturn(9999);
        stubRequest("localhost", 3001, "/mcp");
        when(request.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(rewrittenRequest);
        verify(request).withService(any(HttpService.class));
    }

    /**
     * Query-string irrelevance: only the path component participates in the match. Burp's
     * parameter-pollution probes append arbitrary query params and must still be rewritten when the
     * path still equals the MCP endpoint path.
     */
    @Test
    void pathWithQueryStringStillMatchesWhenPathComponentMatches() {
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:3001/message?session=abc");
        when(proxy.port()).thenReturn(9999);
        stubRequest("localhost", 3001, "/message");
        when(request.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(rewrittenRequest);
        verify(request).withService(any(HttpService.class));
    }

    /**
     * Body / content-type irrelevance: the handler doesn't inspect the body. Same-path requests are
     * rewritten regardless.
     */
    @Test
    void rewritesEvenIfContentTypeIsNotJson_whenPathMatchesEndpoint() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:3001/mcp");
        when(proxy.port()).thenReturn(9999);
        stubRequest("localhost", 3001, "/mcp");
        when(request.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(rewrittenRequest);
        verify(request).withService(any(HttpService.class));
    }

    /**
     * Well-known OAuth metadata probes (PRM / AS) sit on the same host as the MCP endpoint but on a
     * different path. They MUST pass through to Burp's normal HTTP delivery so the MCP OAuth
     * Metadata SSRF check can read the real upstream's response (status + body + WWW-Authenticate).
     * Previously the handler rewrote anything on host+port through the local proxy, which returned
     * 405 for GET and stripped headers — killing the check's three probes.
     */
    @Test
    void wellKnownOauthProtectedResourcePathPassesThroughUntouched() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://127.0.0.1:8000/mcp");
        stubRequest("127.0.0.1", 8000, "/.well-known/oauth-protected-resource");

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(request);
        verify(request, never()).withService(any(HttpService.class));
        verify(annotations, never()).setNotes(any());
    }

    @Test
    void wellKnownOauthAuthorizationServerPathPassesThroughUntouched() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://127.0.0.1:8000/mcp");
        stubRequest("127.0.0.1", 8000, "/.well-known/oauth-authorization-server");

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(request);
        verify(request, never()).withService(any(HttpService.class));
        verify(annotations, never()).setNotes(any());
    }

    /**
     * Burp Scanner's backup-file / path-walking probes (e.g. "/v1/mcp/authv2 (copy)",
     * "/v1/mcp/authv2:twciaf.css") differ in their path component from the MCP endpoint, so under
     * the path-match policy they pass through. Their previous interception was a defence against
     * upstreams that returned SSE for ALL paths on the host — operators whose servers do that should
     * scope Burp out of those paths via Target scope.
     */
    @Test
    void backupFileSuffixedPathPassesThroughUntouched() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("https://mcp.example.com/v1/mcp/authv2");
        stubRequest("mcp.example.com", 443, "/v1/mcp/authv2%20(copy)");

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(request);
        verify(request, never()).withService(any(HttpService.class));
    }

    @Test
    void completelyDifferentPathOnSameHostPassesThroughUntouched() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("https://mcp.example.com/v1/mcp/authv2");
        stubRequest("mcp.example.com", 443, "/v1/mcp/Copy%20of%20authv2");

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(request);
        verify(request, never()).withService(any(HttpService.class));
    }

    /**
     * Root-path regression: when the configured endpoint has no explicit path (e.g.
     * {@code https://mcp.example.com}), {@link URI#getPath()} returns the empty string but Burp
     * normalizes the request path to {@code "/"}. Without empty-path normalization the comparison
     * silently fails and every scan bypasses the local SSE proxy, so Burp tries to scan the
     * upstream's streaming response directly and aborts the audit.
     */
    @Test
    void proxyTargetMatchesRootPathEndpointAgainstSlashRequest() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("https://mcp.example.com");
        when(proxy.port()).thenReturn(9999);
        stubRequest("mcp.example.com", 443, "/");
        when(request.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(rewrittenRequest);
        verify(request).withService(any(HttpService.class));
    }

    @Test
    void proxyTargetMatchesRootPathEndpointWithTrailingSlash() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("https://mcp.example.com/");
        when(proxy.port()).thenReturn(9999);
        stubRequest("mcp.example.com", 443, "/");
        when(request.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(rewrittenRequest);
        verify(request).withService(any(HttpService.class));
    }

    @Test
    void mcpEndpointPathStillGetsRewritten() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://127.0.0.1:8000/mcp");
        when(proxy.port()).thenReturn(9999);
        stubRequest("127.0.0.1", 8000, "/mcp");
        when(request.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(rewrittenRequest);
        verify(request).withService(any(HttpService.class));
    }

    @Test
    void doesNotRewriteRequestToDifferentHost() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:3001/mcp");
        when(request.httpService()).thenReturn(httpService);
        when(httpService.host()).thenReturn("other-host.com");
        when(request.annotations()).thenReturn(annotations);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(request);
        verify(annotations, never()).setNotes(any());
    }

    @Test
    void doesNotRewriteWhenTransportIsNeitherSseNorStreamableHttp() {
        when(scannerSession.transportType()).thenReturn(null);
        when(request.annotations()).thenReturn(annotations);
        when(request.httpService()).thenReturn(httpService);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(request);
        verify(annotations, never()).setNotes(any());
    }

    @Test
    void doesNotRewriteWhenEndpointNotResolved() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn(null);
        when(request.httpService()).thenReturn(httpService);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(request);
    }

    @Test
    void unmarkedRequestOnHttpTransportGoesStraightToTheRealServer() {
        for (TransportType transport : new TransportType[]{TransportType.STREAMABLE_HTTP, TransportType.MODERN_HTTP}) {
            when(scannerSession.transportType()).thenReturn(transport);
            when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:3001/mcp");
            stubRequest("localhost", 3001, "/mcp");
            when(request.headers()).thenReturn(java.util.List.of());

            RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

            assertThat(result.request()).isSameAs(request);
        }
        verify(request, never()).withService(any(HttpService.class));
    }

    @Test
    void stripAuthProbeOnHttpTransportStillGoesThroughTheProxy() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:3001/mcp");
        when(proxy.port()).thenReturn(9999);
        stubRequest("localhost", 3001, "/mcp");
        var stripAuth = sentinel(ScannerSentinels.STRIP_AUTH_HEADER);
        when(request.headers()).thenReturn(java.util.List.of(stripAuth));
        when(request.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        assertThat(handler.handleHttpRequestToBeSent(request).request()).isSameAs(rewrittenRequest);
    }

    @ParameterizedTest
    @EnumSource(value = TransportType.class, names = {"MODERN_HTTP", "STREAMABLE_HTTP"})
    void identityProbeOnHttpTransportGoesThroughTheProxy(TransportType transport) {
        when(scannerSession.transportType()).thenReturn(transport);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:3001/mcp");
        when(proxy.port()).thenReturn(9999);
        stubRequest("localhost", 3001, "/mcp");
        var identity = sentinel(ScannerSentinels.IDENTITY_HEADER);
        when(request.headers()).thenReturn(java.util.List.of(identity));
        when(request.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        assertThat(handler.handleHttpRequestToBeSent(request).request()).isSameAs(rewrittenRequest);
    }

    @Test
    void unmarkedRequestOnSseTransportStillGoesThroughTheProxy() {
        when(scannerSession.transportType()).thenReturn(TransportType.SSE);
        when(scannerSession.resolvedEndpoint()).thenReturn("http://localhost:3001/message");
        when(proxy.port()).thenReturn(9999);
        stubRequest("localhost", 3001, "/message");
        when(request.headers()).thenReturn(java.util.List.of());
        when(request.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        assertThat(handler.handleHttpRequestToBeSent(request).request()).isSameAs(rewrittenRequest);
    }

    @Test
    void passesResponseThrough() {
        ResponseReceivedAction result = handler.handleHttpResponseReceived(response);

        assertThat(result.response()).isSameAs(response);
    }

    @Test
    void answersHttp2EndpointRequestWithTheLoopbackResponseBecauseBurpCannotSpeakHttp2ToAPlaintextProxy() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("https://mcp.example.com/mcp");
        when(proxy.port()).thenReturn(9999);
        stubRequest("mcp.example.com", 443, "/mcp");
        when(relay.needsRelay(request)).thenReturn(true);
        when(relay.relay(org.mockito.ArgumentMatchers.eq(request), proxyService())).thenReturn(java.util.Optional.of(loopbackResponse));

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.action()).isEqualTo(RequestAction.SPOOF_RESPONSE);
        assertThat(((SpoofedRequestAction) result).response()).isSameAs(loopbackResponse);
        verify(request, never()).withService(any(HttpService.class));
    }

    @Test
    void fallsBackToRedirectingWhenTheLoopbackRelayGetsNoResponse() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("https://mcp.example.com/mcp");
        when(proxy.port()).thenReturn(9999);
        stubRequest("mcp.example.com", 443, "/mcp");
        when(relay.needsRelay(request)).thenReturn(true);
        when(relay.relay(org.mockito.ArgumentMatchers.eq(request), any(HttpService.class))).thenReturn(java.util.Optional.empty());
        when(request.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(rewrittenRequest);
    }

    @Test
    void http1EndpointRequestIsRedirectedWithoutRelaying() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("https://mcp.example.com/mcp");
        when(proxy.port()).thenReturn(9999);
        stubRequest("mcp.example.com", 443, "/mcp");
        when(request.withService(any(HttpService.class))).thenReturn(rewrittenRequest);

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(rewrittenRequest);
        verify(relay, never()).relay(any(), any());
    }

    @Test
    void relayedRequestToTheLoopbackProxyKeepsItsAuditCapability() {
        when(scannerSession.transportType()).thenReturn(TransportType.STREAMABLE_HTTP);
        when(scannerSession.resolvedEndpoint()).thenReturn("https://mcp.example.com/mcp");
        when(proxy.port()).thenReturn(9999);
        stubRequest("127.0.0.1", 9999, "/mcp");

        RequestToBeSentAction result = handler.handleHttpRequestToBeSent(request);

        assertThat(result.request()).isSameAs(request);
        verify(request, never()).withRemovedHeaders(org.mockito.ArgumentMatchers.<java.util.List<burp.api.montoya.http.message.HttpHeader>>any());
    }

    private static HttpService proxyService() {
        return org.mockito.ArgumentMatchers.argThat(service ->
                service.host().equals("127.0.0.1") && service.port() == 9999 && !service.secure());
    }

    private void stubRequest(String host, int port, String pathWithoutQuery) {
        when(request.httpService()).thenReturn(httpService);
        when(httpService.host()).thenReturn(host);
        when(httpService.port()).thenReturn(port);
        when(request.pathWithoutQuery()).thenReturn(pathWithoutQuery);
        when(request.annotations()).thenReturn(annotations);
        when(request.toolSource()).thenReturn(toolSource);
        var capability = sentinel(ScannerSentinels.AUDIT_CAPABILITY_HEADER);
        when(request.headers()).thenReturn(java.util.List.of(capability));
        when(request.withRemovedHeaders(java.util.List.of(capability))).thenReturn(request);
    }

    private static burp.api.montoya.http.message.HttpHeader sentinel(String name) {
        var header = org.mockito.Mockito.mock(burp.api.montoya.http.message.HttpHeader.class);
        when(header.name()).thenReturn(name);
        return header;
    }
}
