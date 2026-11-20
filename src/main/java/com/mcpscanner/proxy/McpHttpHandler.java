package com.mcpscanner.proxy;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.client.ConnectedEndpoint;

import java.net.URI;
import java.util.List;
import java.util.Optional;

/**
 * Burp {@link HttpHandler} that rewrites matching outbound MCP requests to target the local
 * {@link SseProxyServer} instead of the real upstream. The redirection exists because Burp's
 * scanner cannot consume streaming SSE responses, so SSE traffic has to be terminated and
 * reshaped into a bounded HTTP reply by the local proxy first. On HTTP transports only requests
 * carrying a scanner sentinel header are rewritten; anything else goes to the real server as-is.
 *
 * <p>Match on host + port + path component of the configured MCP endpoint. Only the path is
 * compared; query string and method are ignored so backup-file probes (e.g. {@code ?qwe9fx.css},
 * {@code OPTIONS} preflights) against the same path still flow through the proxy's gate. Anything
 * on a DIFFERENT path on the same host — including OAuth well-known metadata probes
 * ({@code /.well-known/oauth-protected-resource}, {@code /.well-known/oauth-authorization-server})
 * issued by our own checks — passes through to Burp's normal HTTP delivery so it reaches the real
 * upstream with full request and response headers preserved.
 *
 * @implNote Do not refactor this into a synchronous intercept-and-respond
 * ({@code RequestToBeSentAction.continueWith(...)} returning a synthesised response). That has
 * been tried; this hook does not fire in time relative to Burp's scanner pipeline and the request
 * is sent on the wire before the synthesised response is ready. The handler must stay a pure
 * service-swap and let {@link SseProxyServer} do the real work.
 *
 * <p>Exception: the proxy is plaintext HTTP/1.1, and Burp fixes a request's HTTP/2 mode before this
 * hook runs, so a service swap for a request Burp must send as HTTP/2 fails with "HTTP/2 is
 * currently only supported over TLS". HTTP/2 requests, and requests from tools other than the
 * Scanner (whose HTTP mode is not visible here), are therefore relayed to the proxy over HTTP/1.1
 * by {@link Http1LoopbackRelay} and answered with {@code RequestToBeSentAction.spoof}, which Burp
 * applies before opening any connection. Scanner HTTP/1 requests keep the plain service swap so
 * Burp measures their response timing.
 */
public class McpHttpHandler implements HttpHandler {

    private static final String LOOPBACK_HOST = "127.0.0.1";

    private final ProxyRouting routing;
    private final SseProxyServer proxy;
    private final Http1LoopbackRelay relay;

    public McpHttpHandler(ConnectedEndpoint endpoint, SseProxyServer proxy, Http1LoopbackRelay relay) {
        this.routing = new ProxyRouting(endpoint);
        this.proxy = proxy;
        this.relay = relay;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        if (request.hasHeader(ScannerSentinels.DIRECT_DELIVERY_HEADER)) {
            return RequestToBeSentAction.continueWith(directDelivery(request));
        }
        Optional<URI> target = routing.target(request);
        if (target.isPresent()) {
            request.annotations().setNotes("→ " + target.get().getHost());
            return routeThroughProxy(request);
        }
        if (isBoundForProxy(request.httpService())) {
            return RequestToBeSentAction.continueWith(keyedUnlessFromBurpProxy(request));
        }
        return RequestToBeSentAction.continueWith(withoutUpstreamOnlySentinels(request));
    }

    private HttpRequest keyedUnlessFromBurpProxy(HttpRequestToBeSent request) {
        return request.toolSource().isFromTool(ToolType.PROXY) ? request : keyed(request);
    }

    public HttpRequest route(HttpRequest request) {
        if (request.hasHeader(ScannerSentinels.DIRECT_DELIVERY_HEADER)) {
            return directDelivery(request);
        }
        return routing.target(request).isEmpty() ? request : keyed(request).withService(proxyService());
    }

    private HttpRequest keyed(HttpRequest request) {
        return request.withHeader(ScannerSentinels.ROUTED_HEADER, proxy.routingKey().value());
    }

    private static HttpRequest directDelivery(HttpRequest request) {
        return withoutUpstreamOnlySentinels(request.withRemovedHeader(ScannerSentinels.DIRECT_DELIVERY_HEADER));
    }

    private static HttpRequest withoutUpstreamOnlySentinels(HttpRequest request) {
        List<HttpHeader> sentinels = request.headers().stream()
                .filter(header -> ScannerSentinels.STRIPPED_BEFORE_UPSTREAM.contains(header.name()))
                .toList();
        return sentinels.isEmpty() ? request : request.withRemovedHeaders(sentinels);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        return ResponseReceivedAction.continueWith(response);
    }

    private RequestToBeSentAction routeThroughProxy(HttpRequestToBeSent request) {
        HttpService proxyService = proxyService();
        HttpRequest keyed = keyed(request);
        if (relay.needsRelay(request)) {
            Optional<HttpResponse> relayed = relay.relay(keyed, proxyService);
            if (relayed.isPresent()) {
                return RequestToBeSentAction.spoof(relayed.get(), request.annotations());
            }
        }
        return RequestToBeSentAction.continueWith(keyed.withService(proxyService));
    }

    private HttpService proxyService() {
        return HttpService.httpService(LOOPBACK_HOST, proxy.port(), false);
    }

    private boolean isBoundForProxy(HttpService service) {
        return LOOPBACK_HOST.equals(service.host()) && service.port() == proxy.port();
    }

}
