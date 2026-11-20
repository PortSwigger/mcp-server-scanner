package com.mcpscanner.proxy;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.client.RedirectLoggingInterceptor;
import com.mcpscanner.config.RedirectMode;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SseMessagePosterTest {

    private static final String BODY = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}";

    private HttpServer server;

    @BeforeEach
    void startServer() throws IOException {
        MontoyaTestFactory.install();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/message", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().set("Location", "/moved?session=1");
            exchange.sendResponseHeaders(307, -1);
            exchange.close();
        });
        server.createContext("/moved", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(202, -1);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void evidenceOfARedirectedPostIsTheFinalHopRequestWithItsResponse() throws Exception {
        MessagePostResult result = poster().post(endpoint("/message"), BODY, Map.of());

        HttpRequestResponse evidence = result.exchange().evidence().get(0);
        String request = evidence.request().toByteArray().toString();
        assertThat(evidence.response().statusCode()).isEqualTo((short) 202);
        assertThat(request).startsWith("POST /moved?session=1 HTTP/1.1\r\n");
        assertThat(evidence.request().bodyToString()).isEqualTo(BODY);
    }

    private SseMessagePoster poster() {
        HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        RedirectLoggingInterceptor redirects = new RedirectLoggingInterceptor(new McpEventLog(null),
                () -> RedirectMode.METHOD_PRESERVING_SAME_ORIGIN);
        return new SseMessagePoster(client, redirects, Duration.ofSeconds(5), new SessionLifecycle());
    }

    private String endpoint(String path) {
        return "http://127.0.0.1:" + server.getAddress().getPort() + path;
    }
}
