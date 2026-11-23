package com.mcpscanner.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mcpscanner.client.FixtureSseStreams;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

final class ServiceAccountFixtureServer implements AutoCloseable {

    private static final String BEARER = "Bearer ";
    private static final String SERVICE_ACCOUNT = "svc-internal";
    private static final Map<String, String> API_KEYS = Map.of("alice-token", "alice");
    private static final Set<String> ADMIN_TOOLS = Set.of("list_users", "delete_user");
    private static final String USER_TOOLS = "{\"name\":\"whoami\",\"inputSchema\":{\"type\":\"object\"},"
            + "\"annotations\":{\"readOnlyHint\":true}}";
    private static final String SERVICE_TOOLS = USER_TOOLS
            + ",{\"name\":\"list_users\",\"inputSchema\":{\"type\":\"object\"},\"annotations\":{\"readOnlyHint\":true}}"
            + ",{\"name\":\"delete_user\",\"inputSchema\":{\"type\":\"object\"},"
            + "\"annotations\":{\"destructiveHint\":true}}";

    private final boolean unknownKeyFallsBackToServiceAccount;
    private final HttpServer server;
    private final FixtureSseStreams streams = new FixtureSseStreams();
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final ObjectMapper json = new ObjectMapper();
    final List<String> calls = new CopyOnWriteArrayList<>();

    private ServiceAccountFixtureServer(boolean unknownKeyFallsBackToServiceAccount) throws IOException {
        this.unknownKeyFallsBackToServiceAccount = unknownKeyFallsBackToServiceAccount;
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(executor);
        server.createContext("/mcp", this::serve);
        server.createContext("/messages", this::serveSseMessage);
        server.start();
    }

    static ServiceAccountFixtureServer unknownKeyFallsBackToServiceAccount() throws IOException {
        return new ServiceAccountFixtureServer(true);
    }

    static ServiceAccountFixtureServer unknownKeyRejected() throws IOException {
        return new ServiceAccountFixtureServer(false);
    }

    String endpoint() {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/mcp";
    }

    private void serve(HttpExchange exchange) throws IOException {
        if (exchange.getRequestMethod().equals("GET")) {
            openSseStream(exchange);
            return;
        }
        try (exchange) {
            if (!exchange.getRequestMethod().equals("POST")) {
                reply(exchange, 405, "");
                return;
            }
            Optional<String> caller = authenticate(exchange.getRequestHeaders().getFirst("Authorization"));
            JsonNode request = json.readTree(exchange.getRequestBody());
            if (caller.isEmpty()) {
                reply(exchange, 401, "{\"error\":\"invalid_token\"}");
                return;
            }
            if (!request.has("id")) {
                reply(exchange, 202, "");
                return;
            }
            reply(exchange, 200, envelope(request, caller.get()));
        }
    }

    private void openSseStream(HttpExchange exchange) throws IOException {
        String streamId = streams.open(exchange);
        streams.send(streamId, "endpoint", "/messages?session=" + streamId);
    }

    private void serveSseMessage(HttpExchange exchange) throws IOException {
        try (exchange) {
            Optional<String> caller = authenticate(exchange.getRequestHeaders().getFirst("Authorization"));
            JsonNode request = json.readTree(exchange.getRequestBody());
            if (caller.isEmpty()) {
                reply(exchange, 401, "{\"error\":\"invalid_token\"}");
                return;
            }
            if (request.has("id")) {
                String streamId = exchange.getRequestURI().getQuery().substring("session=".length());
                streams.send(streamId, "message", envelope(request, caller.get()));
            }
            reply(exchange, 202, "");
        }
    }

    private String envelope(JsonNode request, String caller) {
        return "{\"jsonrpc\":\"2.0\",\"id\":" + request.get("id") + "," + answer(request, caller) + "}";
    }

    private Optional<String> authenticate(String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER)) {
            return Optional.empty();
        }
        String user = API_KEYS.get(authorization.substring(BEARER.length()));
        if (user == null && unknownKeyFallsBackToServiceAccount) {
            return Optional.of(SERVICE_ACCOUNT);
        }
        return Optional.ofNullable(user);
    }

    private String answer(JsonNode request, String caller) {
        return switch (request.path("method").asText()) {
            case "initialize" -> "\"result\":{\"protocolVersion\":\""
                    + request.path("params").path("protocolVersion").asText()
                    + "\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"svc\",\"version\":\"1\"}}";
            case "tools/list" -> "\"result\":{\"tools\":[" + (isService(caller) ? SERVICE_TOOLS : USER_TOOLS) + "]}";
            case "tools/call" -> call(request.path("params").path("name").asText(), caller);
            default -> "\"result\":{}";
        };
    }

    private String call(String tool, String caller) {
        calls.add(caller + ":" + tool);
        if (ADMIN_TOOLS.contains(tool) && !isService(caller)) {
            return "\"error\":{\"code\":-32602,\"message\":\"Unknown tool: " + tool + "\"}";
        }
        String text = switch (tool) {
            case "whoami" -> "you are " + caller;
            case "list_users" -> "users: alice (admin), bob, carol";
            case "delete_user" -> "deleted nobody";
            default -> "unknown";
        };
        return "\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"" + text + "\"}]}";
    }

    private static boolean isService(String caller) {
        return SERVICE_ACCOUNT.equals(caller);
    }

    private static void reply(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            exchange.getResponseBody().write(bytes);
        }
    }

    @Override
    public void close() {
        streams.close();
        server.stop(0);
        executor.shutdownNow();
    }
}
