package com.mcpscanner.client;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.Audit;

import java.net.URI;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Adapter that bridges {@link CapturedExchange} discovery captures into Burp's
 * passive-scan engine.
 *
 * <p>Each accepted exchange is reconstituted as a synthesised
 * {@link HttpRequestResponse} and pushed through {@link Audit#addRequestResponse},
 * which is the call Burp invokes registered {@link
 * burp.api.montoya.scanner.scancheck.PassiveScanCheck} implementations on. Our
 * {@code JsonRpcDiscoveryResponseScanner} is the primary
 * consumer; Burp's built-in passive checks also see the pair, but the synthesised
 * body is a pure JSON-RPC envelope (no HTML / SQL / shell patterns) so the
 * built-ins should not false-positive.
 *
 * <p>The {@code Supplier<Audit>} indirection lets {@link McpClientManager} swap
 * the underlying Audit at Connect / Disconnect without rewiring the publisher
 * chain inside the {@link CapturingMcpTransport} decorator.
 */
final class McpDiscoveryAuditBridge implements Consumer<CapturedExchange> {

    private final Supplier<Audit> auditSupplier;

    McpDiscoveryAuditBridge(Supplier<Audit> auditSupplier) {
        this.auditSupplier = auditSupplier;
    }

    @Override
    public void accept(CapturedExchange exchange) {
        if (exchange == null) {
            return;
        }
        Audit audit = auditSupplier.get();
        if (audit == null) {
            return;
        }
        try {
            HttpRequestResponse pair = synthesise(exchange);
            if (pair != null) {
                audit.addRequestResponse(pair);
            }
        } catch (RuntimeException ignored) {
            // Synthesis failures must never poison the langchain4j discovery future.
        }
    }

    private static HttpRequestResponse synthesise(CapturedExchange exchange) {
        HttpRequest request = synthesiseRequest(exchange);
        HttpResponse response = synthesiseResponse(exchange);
        if (request == null || response == null) {
            return null;
        }
        return HttpRequestResponse.httpRequestResponse(request, response);
    }

    private static HttpRequest synthesiseRequest(CapturedExchange exchange) {
        URI url = exchange.url();
        if (url == null) {
            return null;
        }
        HttpService service = serviceFor(url);
        HttpRequest request = HttpRequest.httpRequestFromUrl(url.toString())
                .withService(service)
                .withMethod("POST")
                .withBody(exchange.requestBody() == null ? "" : exchange.requestBody());
        if (exchange.requestHeaders() != null) {
            for (Map.Entry<String, String> header : exchange.requestHeaders().entrySet()) {
                request = request.withAddedHeader(header.getKey(), header.getValue());
            }
        }
        return request;
    }

    private static HttpResponse synthesiseResponse(CapturedExchange exchange) {
        if (exchange.responseEnvelope() == null) {
            return null;
        }
        String body = exchange.responseEnvelope().toString();
        String rawResponse = "HTTP/1.1 200 OK\r\n"
                + "Content-Type: application/json\r\n"
                + "Content-Length: " + body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length + "\r\n"
                + "\r\n"
                + body;
        return HttpResponse.httpResponse(rawResponse);
    }

    private static HttpService serviceFor(URI url) {
        boolean secure = "https".equalsIgnoreCase(url.getScheme());
        int port = url.getPort() != -1 ? url.getPort() : (secure ? 443 : 80);
        return HttpService.httpService(url.getHost(), port, secure);
    }
}
