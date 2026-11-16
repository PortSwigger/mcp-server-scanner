package com.mcpscanner.checks.catalog.downstreamrouteescape;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

final class RouteModelServer implements AutoCloseable {

    enum PathBuilding { RAW_JOIN, RAW_JOIN_BEFORE_FIXED_SUFFIX, ENCODED_SEGMENT_RESOLVED, ENCODED_SEGMENT }

    private static final String NOT_FOUND = "{\"error\":\"not found\"}";
    private static final ObjectMapper JSON = new ObjectMapper();

    private final PathBuilding pathBuilding;
    private final boolean unknownValueIsToolError;
    private final HttpServer server;
    final AtomicInteger requests = new AtomicInteger();

    RouteModelServer(PathBuilding pathBuilding) throws IOException {
        this(pathBuilding, false);
    }

    RouteModelServer(PathBuilding pathBuilding, boolean unknownValueIsToolError) throws IOException {
        this.pathBuilding = pathBuilding;
        this.unknownValueIsToolError = unknownValueIsToolError;
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/mcp", this::respond);
        server.start();
    }

    String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/mcp";
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private void respond(HttpExchange exchange) throws IOException {
        requests.incrementAndGet();
        JsonNode request = JSON.readTree(exchange.getRequestBody());
        ObjectNode reply = JSON.createObjectNode().put("jsonrpc", "2.0");
        reply.set("id", request.path("id"));
        reply.set("result", result(request));
        byte[] body = JSON.writeValueAsBytes(reply);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private JsonNode result(JsonNode request) {
        if (!"tools/call".equals(request.path("method").asText())) {
            return JSON.createObjectNode().set("tools", JSON.createArrayNode());
        }
        JsonNode arguments = request.path("params").path("arguments");
        return switch (request.path("params").path("name").asText()) {
            case "get_item" -> item(api(downstreamPath(arguments.path("id").asText())));
            case "echo" -> text("you said " + arguments.path("text").asText());
            case "normalize" -> text(URI.create(arguments.path("path").asText().replace("?", "")).normalize()
                    .getPath());
            default -> JSON.createObjectNode().put("isError", true);
        };
    }

    private String downstreamPath(String id) {
        String encoded = URLEncoder.encode(id, StandardCharsets.UTF_8);
        return switch (pathBuilding) {
            case RAW_JOIN -> URI.create("/api/items/" + id).normalize().getPath();
            case RAW_JOIN_BEFORE_FIXED_SUFFIX -> URI.create("/api/items/" + id + "/profile").normalize().getPath();
            case ENCODED_SEGMENT_RESOLVED -> URI.create("/api/items/" + encoded).normalize().getPath();
            case ENCODED_SEGMENT -> "/api/items/" + encoded;
        };
    }

    private static String api(String path) {
        return switch (path) {
            case "/api/", "/api" -> "{\"service\":\"inventory\",\"collections\":[\"items\"]}";
            case "/api/items/A1", "/api/items/A1/profile" -> "{\"item\":\"A1\"}";
            default -> NOT_FOUND;
        };
    }

    private JsonNode item(String body) {
        JsonNode result = text(body);
        if (unknownValueIsToolError && body.contains(NOT_FOUND)) {
            ((ObjectNode) result).put("isError", true);
        }
        return result;
    }

    private static JsonNode text(String text) {
        ObjectNode result = JSON.createObjectNode().put("isError", false);
        result.putArray("content").addObject().put("type", "text").put("text", text);
        return result;
    }
}
