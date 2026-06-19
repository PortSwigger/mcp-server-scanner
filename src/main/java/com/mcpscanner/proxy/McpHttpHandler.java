package com.mcpscanner.proxy;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.client.TransportType;

import java.net.URI;
import java.util.Objects;

/**
 * Burp {@link HttpHandler} that rewrites matching outbound MCP requests to target the local
 * {@link SseProxyServer} instead of the real upstream. The redirection exists because Burp's
 * scanner cannot consume streaming SSE responses, so SSE traffic has to be terminated and
 * reshaped into a bounded HTTP reply by the local proxy first.
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
 */
public class McpHttpHandler implements HttpHandler {

    private final McpScannerSession scannerSession;
    private final SseProxyServer proxy;

    public McpHttpHandler(McpScannerSession scannerSession, SseProxyServer proxy) {
        this.scannerSession = scannerSession;
        this.proxy = proxy;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        URI target = proxyTarget(request);
        if (target != null) {
            request.annotations().setNotes("→ " + target.getHost());
            return RequestToBeSentAction.continueWith(
                    request.withService(HttpService.httpService("127.0.0.1", proxy.port(), false)));
        }
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        return ResponseReceivedAction.continueWith(response);
    }

    private URI proxyTarget(HttpRequestToBeSent request) {
        TransportType transport = scannerSession.transportType();
        if (transport != TransportType.STREAMABLE_HTTP && transport != TransportType.SSE) {
            return null;
        }
        String endpoint = scannerSession.resolvedEndpoint();
        if (endpoint == null) {
            return null;
        }
        URI target = URI.create(endpoint);
        HttpService service = request.httpService();
        if (!target.getHost().equals(service.host()) || effectivePort(target) != service.port()) {
            return null;
        }
        if (!Objects.equals(normalizePath(target.getPath()), normalizePath(request.pathWithoutQuery()))) {
            return null;
        }
        return target;
    }

    private static int effectivePort(URI uri) {
        int port = uri.getPort();
        if (port != -1) {
            return port;
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private static String normalizePath(String path) {
        return (path == null || path.isEmpty()) ? "/" : path;
    }
}
