package com.mcpscanner.checks.catalog.commandinjection;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class LoopbackStreamingServer implements AutoCloseable {

    private final HttpServer server;
    private final List<String> requestBodies = Collections.synchronizedList(new ArrayList<>());

    LoopbackStreamingServer(SimulatedToolServer tools) throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/mcp", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            requestBodies.add(body);
            byte[] reply = tools.replyTo(request(body)).bodyToString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "text/event-stream");
            exchange.sendResponseHeaders(200, reply.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(reply);
            }
        });
        server.start();
    }

    String endpoint() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/mcp";
    }

    List<String> requestBodies() {
        return List.copyOf(requestBodies);
    }

    private HttpRequest request(String body) {
        return HttpRequest.httpRequestFromUrl(endpoint()).withMethod("POST").withBody(body);
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
