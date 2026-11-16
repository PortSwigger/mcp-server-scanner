package com.mcpscanner.auth.oauth.discovery;

import com.mcpscanner.auth.oauth.safety.SuspiciousDestinationGate;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.RecordingRealHttp;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

class StrictStreamableServerProbeTest {

    private static final int NOT_ACCEPTABLE = 406;
    private static final int UNAUTHORIZED = 401;
    private static final int OK = 200;
    private static final String INITIALIZE_REPLY =
            "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-03-26\"}}\n\n";

    private final List<String> hostsSeen = new CopyOnWriteArrayList<>();
    private HttpServer server;
    private AuthRequirementProbe probe;

    @BeforeEach
    void startServer() throws IOException {
        MontoyaTestFactory.install();
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/mcp", this::answerLikeApolloMcpServer);
        server.start();
        RecordingRealHttp http = new RecordingRealHttp();
        OAuthMetadataDiscoverer discoverer = OAuthMetadataDiscoverer.defaultInstance(http, McpEventLog.noop(),
                (url, purpose) -> SuspiciousDestinationGate.Decision.allow());
        probe = new AuthRequirementProbe(http, discoverer);
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void serverThatAcceptsAnonymousInitializeButChallengesAnonymousStreamGetNeedsNoAuth() {
        URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/mcp");

        AuthRequirement requirement = probe.probe(endpoint, ChallengeStrategy.POST_THEN_STREAM_GET);

        assertThat(requirement).isInstanceOf(AuthRequirement.NotRequired.class);
    }

    @Test
    void everyProbeSendsTheEndpointAuthorityAsHost() {
        int port = server.getAddress().getPort();

        probe.probe(URI.create("http://127.0.0.1:" + port + "/mcp"), ChallengeStrategy.POST_THEN_STREAM_GET);

        assertThat(hostsSeen).isNotEmpty().containsOnly("127.0.0.1:" + port);
    }

    private void answerLikeApolloMcpServer(HttpExchange exchange) throws IOException {
        hostsSeen.add(exchange.getRequestHeaders().getFirst("Host"));
        String accept = exchange.getRequestHeaders().getFirst("Accept");
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        if (!"POST".equals(exchange.getRequestMethod())) {
            reply(exchange, UNAUTHORIZED, "");
        } else if (accept == null || !accept.contains("text/event-stream") || !accept.contains("application/json")) {
            reply(exchange, NOT_ACCEPTABLE, "");
        } else if (!body.contains("\"method\":\"initialize\"")) {
            reply(exchange, 422, "");
        } else {
            reply(exchange, OK, INITIALIZE_REPLY);
        }
    }

    private static void reply(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", status == OK ? "text/event-stream" : "text/plain");
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
