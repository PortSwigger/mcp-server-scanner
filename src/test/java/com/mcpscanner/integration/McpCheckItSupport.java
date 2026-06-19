package com.mcpscanner.integration;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.awaitility.Awaitility.await;

final class McpCheckItSupport {

    static final String HOST = "127.0.0.1";
    static final Duration BOOT_TIMEOUT = Duration.ofSeconds(30);
    static final Duration POLL_INTERVAL = Duration.ofMillis(200);
    static final Duration SHUTDOWN_GRACE = Duration.ofSeconds(5);
    static final int BOOT_ATTEMPTS = 4;

    private McpCheckItSupport() {}

    record RunningServer(int port, Process process) implements AutoCloseable {
        @Override
        public void close() throws InterruptedException {
            destroyQuietly(process);
        }
    }

    /**
     * Boots the test-server, retrying the whole launch on a fresh port if the chosen
     * port could not be bound in time.
     *
     * <p>{@link #findFreePort()} closes its probe {@link ServerSocket} before
     * {@code uv run} relaunches uvicorn on that port, so there is a TOCTOU window in
     * which another process can claim the port — uvicorn then fails to bind (or another
     * responder answers readiness probes) and the server never serves MCP traffic. Booting
     * is slowest under {@code --auth oauth} (the DCR fixtures), which widens the window.
     * Re-picking the port and relaunching a bounded number of times eliminates the flake
     * without serialising the suite.
     */
    static RunningServer startServer(String... cliArgs) throws IOException, InterruptedException {
        return startServer(java.util.Map.of(), cliArgs);
    }

    static RunningServer startServer(java.util.Map<String, String> extraEnv, String... cliArgs)
            throws IOException, InterruptedException {
        RuntimeException lastFailure = null;
        for (int attempt = 1; attempt <= BOOT_ATTEMPTS; attempt++) {
            int port = findFreePort();
            Process process = launchServer(port, extraEnv, cliArgs);
            try {
                waitForReadiness(mcpEndpoint(port), process);
                return new RunningServer(port, process);
            } catch (RuntimeException readinessFailure) {
                lastFailure = readinessFailure;
                destroyQuietly(process);
            }
        }
        throw new IllegalStateException(
                "test-server failed to become ready after " + BOOT_ATTEMPTS + " attempts", lastFailure);
    }

    private static Process launchServer(int port, java.util.Map<String, String> extraEnv,
                                        String[] cliArgs) throws IOException {
        ProcessBuilder builder = new ProcessBuilder(buildCommand(port, cliArgs))
                .directory(resolveTestServerDir())
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.INHERIT);
        builder.environment().putAll(extraEnv);
        return builder.start();
    }

    private static void destroyQuietly(Process process) throws InterruptedException {
        process.destroy();
        if (!process.waitFor(SHUTDOWN_GRACE.toSeconds(), TimeUnit.SECONDS)) {
            process.destroyForcibly();
        }
    }

    static String mcpEndpoint(int port) {
        return "http://" + HOST + ":" + port + "/mcp";
    }

    static HttpClient realHttpClient() {
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    /**
     * Performs an MCP initialize handshake and returns the Mcp-Session-Id.
     * Returns null if the server doesn't require session IDs (older servers).
     */
    static String initializeSession(int port) throws Exception {
        return sendInitialize(port, null).headers().firstValue("mcp-session-id").orElse(null);
    }

    /**
     * Sends an MCP initialize request authenticated with the given bearer token and
     * returns the Mcp-Session-Id from the response. Throws if the server rejects the token.
     */
    static String initializeSessionWithBearer(int port, String bearerToken) throws Exception {
        HttpResponse<String> response = sendInitialize(port, bearerToken);
        String sessionId = response.headers().firstValue("mcp-session-id").orElse(null);
        if (sessionId == null) {
            throw new IllegalStateException(
                    "Server did not return Mcp-Session-Id; status=" + response.statusCode()
                            + " body=" + response.body());
        }
        return sessionId;
    }

    /**
     * Mints a fresh signer-issued RS256 JWT via the test-server's
     * {@code /test-only/mint-token} endpoint. The server MUST be started with
     * {@code --oauth-test-mint-endpoint} for this to succeed.
     */
    static String mintTestToken(int port) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(
                        URI.create("http://" + HOST + ":" + port + "/test-only/mint-token"))
                .POST(HttpRequest.BodyPublishers.ofString("{}"))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(10))
                .build();
        HttpResponse<String> response = realHttpClient()
                .send(req, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException(
                    "mint-token endpoint returned status=" + response.statusCode()
                            + " body=" + response.body()
                            + " (did you start the server with --oauth-test-mint-endpoint?)");
        }
        JsonNode node = JSON.readTree(response.body());
        JsonNode tokenNode = node.get("access_token");
        if (tokenNode == null || !tokenNode.isTextual() || tokenNode.asText().isBlank()) {
            throw new IllegalStateException(
                    "mint-token response missing access_token; body=" + response.body());
        }
        return tokenNode.asText();
    }

    /**
     * Builds a baseline {@link HttpRequestResponse} that calls {@code user_info(username=alice)}
     * with the supplied session ID and Authorization header. Used by checks that need a
     * tools/call baseline to probe variations from.
     */
    static HttpRequestResponse buildUserInfoBaseline(int port, String sessionId,
                                                     String authHeaderValue) {
        String endpoint = mcpEndpoint(port);
        burp.api.montoya.http.message.requests.HttpRequest request =
                burp.api.montoya.http.message.requests.HttpRequest.httpRequestFromUrl(endpoint)
                        .withMethod("POST")
                        .withBody("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                                + "\"params\":{\"name\":\"user_info\","
                                + "\"arguments\":{\"username\":\"alice\"}}}");
        if (sessionId != null) {
            request = request.withAddedHeader("Mcp-Session-Id", sessionId);
        }
        if (authHeaderValue != null) {
            request = request.withAddedHeader("Authorization", authHeaderValue);
        }
        return HttpRequestResponse.httpRequestResponse(request, null);
    }

    private static HttpResponse<String> sendInitialize(int port, String bearerToken) throws Exception {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\","
                + "\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},"
                + "\"clientInfo\":{\"name\":\"mcp-e2e-test\",\"version\":\"1.0\"}}}";
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(mcpEndpoint(port)))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .timeout(Duration.ofSeconds(10));
        if (bearerToken != null) {
            builder.header("Authorization", "Bearer " + bearerToken);
        }
        return realHttpClient().send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    static HttpRequest toolsListRequest(int port, String bearerToken) {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(mcpEndpoint(port)))
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}"))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(10));
        if (bearerToken != null) {
            builder.header("Authorization", "Bearer " + bearerToken);
        }
        return builder.build();
    }

    static HttpRequest toolsCallRequest(int port, String toolName,
                                        java.util.Map<String, Object> args,
                                        String bearerToken) {
        String argsJson;
        try {
            argsJson = JSON.writeValueAsString(args);
        } catch (Exception e) {
            argsJson = "{}";
        }
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"" + toolName + "\",\"arguments\":" + argsJson + "}}";
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(mcpEndpoint(port)))
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(10));
        if (bearerToken != null) {
            builder.header("Authorization", "Bearer " + bearerToken);
        }
        return builder.build();
    }

    private static String resolveUv() {
        // uv is often installed in ~/.local/bin which may not be on the JVM's PATH
        String[] candidates = {
                System.getProperty("user.home") + "/.local/bin/uv",
                "/usr/local/bin/uv",
                "/opt/homebrew/bin/uv",
                "uv"
        };
        for (String candidate : candidates) {
            if (new File(candidate).canExecute()) {
                return candidate;
            }
        }
        return "uv";
    }

    private static File resolveTestServerDir() {
        // Gradle sets user.dir to the project root during test execution.
        // Walk up from the class file location to find test-server/ relative to the project root.
        String projectDir = System.getProperty("user.dir");
        File candidate = new File(projectDir, "test-server");
        if (candidate.isDirectory()) {
            return candidate;
        }
        // Fallback: search up the directory tree
        File dir = new File(projectDir);
        while (dir != null) {
            File ts = new File(dir, "test-server");
            if (ts.isDirectory()) {
                return ts;
            }
            dir = dir.getParentFile();
        }
        throw new IllegalStateException("Cannot locate test-server/ directory from: " + projectDir);
    }

    private static int findFreePort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static List<String> buildCommand(int port, String[] cliArgs) {
        java.util.List<String> command = new java.util.ArrayList<>();
        command.add(resolveUv());
        command.add("run");
        command.add("--no-sync");
        command.add("mcp-test-server");
        command.add("--host");
        command.add(HOST);
        command.add("--port");
        command.add(String.valueOf(port));
        for (String arg : cliArgs) {
            command.add(arg);
        }
        return command;
    }

    private static void waitForReadiness(String endpoint, Process process) {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .build();
        HttpRequest probe = HttpRequest.newBuilder(URI.create(endpoint))
                .POST(HttpRequest.BodyPublishers.ofString(
                        "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"tools/list\",\"params\":{}}"))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .timeout(Duration.ofSeconds(2))
                .build();
        await().atMost(BOOT_TIMEOUT).pollInterval(POLL_INTERVAL).until(() -> {
            // If uvicorn could not bind the port (TOCTOU race) the process exits early;
            // fail fast so the caller can relaunch on a fresh port instead of waiting out
            // the full boot timeout.
            if (!process.isAlive()) {
                throw new IllegalStateException(
                        "test-server process exited before becoming ready (exit="
                                + process.exitValue() + ") — likely a port bind race");
            }
            try {
                HttpResponse<Void> response = client.send(probe, HttpResponse.BodyHandlers.discarding());
                return response.statusCode() < 500;
            } catch (IOException ignored) {
                return false;
            }
        });
    }
}
