package com.mcpscanner.testutil;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

public final class EvidenceTarget implements AutoCloseable {

    public static final String CREDENTIAL = "Bearer evidence-secret";
    public static final String TOOLS_LIST = "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}";
    public static final String TOOLS_REPLY = "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"tools\":[]}}";
    public static final String TOOLS_EVENT = "id: 1\nevent: message\ndata: " + TOOLS_REPLY + "\n\n";
    public static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final HttpServer server;

    private EvidenceTarget(HttpServer server) {
        this.server = server;
    }

    public static EvidenceTarget start() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", EvidenceTarget::answer);
        server.start();
        return new EvidenceTarget(server);
    }

    public URI endpoint() {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/mcp");
    }

    public static Map<String, String> credentialed() {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", CREDENTIAL);
        headers.put("Content-Type", "application/json");
        headers.put("Accept", "application/json, text/event-stream");
        return headers;
    }

    public static HttpClient jdkClient() {
        return HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(TIMEOUT).build();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private static void answer(HttpExchange exchange) throws IOException {
        exchange.getRequestBody().readAllBytes();
        boolean stream = "GET".equals(exchange.getRequestMethod());
        byte[] body = (stream ? TOOLS_EVENT : TOOLS_REPLY).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", stream ? "text/event-stream" : "application/json");
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }
}
