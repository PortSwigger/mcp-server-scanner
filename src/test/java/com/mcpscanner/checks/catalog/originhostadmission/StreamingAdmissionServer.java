package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class StreamingAdmissionServer implements AutoCloseable {

    private static final String STREAMED = "Streaming response received";
    private static final String LOOPBACK = "127.0.0.1";

    final Http burp = burpWithholdingStreams();
    final List<String> receivedOrigins = new CopyOnWriteArrayList<>();
    final List<String> preflightOrigins = new CopyOnWriteArrayList<>();
    final List<String> receivedHosts = new CopyOnWriteArrayList<>();

    private final HttpServer server;
    private final boolean validatesHeaders;
    private final Set<String> unansweredOrigins;
    private final boolean refusesEveryRequest;

    private StreamingAdmissionServer(boolean validatesHeaders, Set<String> unansweredOrigins,
                                     boolean refusesEveryRequest) throws IOException {
        this.validatesHeaders = validatesHeaders;
        this.unansweredOrigins = unansweredOrigins;
        this.refusesEveryRequest = refusesEveryRequest;
        server = HttpServer.create(new InetSocketAddress(LOOPBACK, 0), 0);
        server.createContext("/mcp", this::respond);
        server.start();
    }

    static Http burpWithholdingStreams() {
        Http burp = mock(Http.class);
        when(burp.sendRequest(any(HttpRequest.class))).thenThrow(new IllegalStateException(STREAMED));
        when(burp.sendRequest(any(HttpRequest.class), any(RequestOptions.class)))
                .thenThrow(new IllegalStateException(STREAMED));
        return burp;
    }

    static StreamingAdmissionServer admittingEveryOrigin() throws IOException {
        return new StreamingAdmissionServer(false, Set.of(), false);
    }

    static StreamingAdmissionServer refusingForeignOriginsAndHosts() throws IOException {
        return new StreamingAdmissionServer(true, Set.of(), false);
    }

    static StreamingAdmissionServer droppingOrigin(String origin) throws IOException {
        return new StreamingAdmissionServer(false, Set.of(origin), false);
    }

    static StreamingAdmissionServer refusingEveryRequest() throws IOException {
        return new StreamingAdmissionServer(false, Set.of(), true);
    }

    String url() {
        return "http://" + LOOPBACK + ":" + server.getAddress().getPort() + "/mcp";
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void respond(HttpExchange exchange) throws IOException {
        exchange.getRequestBody().readAllBytes();
        String origin = exchange.getRequestHeaders().getFirst("Origin");
        String host = exchange.getRequestHeaders().getFirst("Host");
        receivedHosts.add(host);
        if ("OPTIONS".equals(exchange.getRequestMethod())) {
            preflightOrigins.add(origin);
            send(exchange, 204, "text/plain", "");
            return;
        }
        receivedOrigins.add(origin == null ? "(none)" : origin);
        if (origin != null && unansweredOrigins.contains(origin)) {
            exchange.close();
            return;
        }
        if (refusesEveryRequest) {
            send(exchange, 401, "application/json", AdmissionServers.FORBIDDEN);
            return;
        }
        if (validatesHeaders && (origin != null || !host.startsWith(LOOPBACK))) {
            send(exchange, 403, "application/json", AdmissionServers.FORBIDDEN);
            return;
        }
        send(exchange, 200, "text/event-stream", "event: message\ndata: " + AdmissionServers.TOOLS_RESULT + "\n\n");
    }

    private static void send(HttpExchange exchange, int status, String contentType, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", contentType);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
