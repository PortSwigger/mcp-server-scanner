package com.mcpscanner.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JdkProtocolHttpTransportTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final CountDownLatch releaseStalled = new CountDownLatch(1);
    private final HttpClient client = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    private HttpServer server;
    private volatile String receivedMethod;
    private volatile String receivedBody;
    private volatile String receivedSessionHeader;
    private volatile String receivedContentType;

    @BeforeEach
    void startServer() throws IOException {
        MontoyaTestFactory.install();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(executor);
        server.createContext("/mcp", this::echo);
        server.createContext("/moved", exchange -> respond(exchange, 302, "Location", "/mcp", ""));
        server.createContext("/stalled", this::stall);
        server.start();
    }

    @AfterEach
    void stopServer() {
        releaseStalled.countDown();
        server.stop(0);
        executor.shutdownNow();
    }

    @Test
    void postDeliversBodyAndHeaders() throws Exception {
        String json = "{\"text\":\"café 🚀\"}";

        transport().send(new ProtocolHttpRequest(uri("/mcp"), "POST",
                Map.of("Content-Type", "application/json", "Mcp-Session-Id", "abc"), json), TIMEOUT).close();

        assertThat(receivedMethod).isEqualTo("POST");
        assertThat(receivedBody).isEqualTo(json);
        assertThat(receivedContentType).isEqualTo("application/json");
        assertThat(receivedSessionHeader).isEqualTo("abc");
    }

    @Test
    void deleteSendsNoBody() throws Exception {
        transport().send(new ProtocolHttpRequest(uri("/mcp"), "DELETE",
                Map.of("Mcp-Session-Id", "abc"), null), TIMEOUT).close();

        assertThat(receivedMethod).isEqualTo("DELETE");
        assertThat(receivedBody).isEmpty();
        assertThat(receivedSessionHeader).isEqualTo("abc");
    }

    @Test
    void mapsResponseStatusHeadersBodyAndUri() throws Exception {
        ProtocolHttpResponse response = transport().send(
                new ProtocolHttpRequest(uri("/mcp"), "POST", Map.of(), "{}"), TIMEOUT);

        assertThat(response.status()).isEqualTo(201);
        assertThat(response.firstHeader("mcp-session-id")).contains("server-session");
        assertThat(response.headerValues("X-Multi")).containsExactly("one", "two");
        assertThat(response.uri()).isEqualTo(uri("/mcp"));
        try (InputStream body = response.body()) {
            assertThat(new String(body.readAllBytes(), StandardCharsets.UTF_8)).isEqualTo("echo:{}");
        }
    }

    @Test
    void returnsRedirectWithoutFollowingIt() throws Exception {
        ProtocolHttpResponse response = transport().send(
                new ProtocolHttpRequest(uri("/moved"), "GET", Map.of(), null), TIMEOUT);

        assertThat(response.status()).isEqualTo(302);
        assertThat(response.firstHeader("Location")).contains("/mcp");
        assertThat(response.uri()).isEqualTo(uri("/moved"));
        assertThat(receivedMethod).isNull();
    }

    @Test
    void honoursTheTimeout() {
        assertThatThrownBy(() -> transport().send(
                new ProtocolHttpRequest(uri("/stalled"), "POST", Map.of(), "{}"), Duration.ofMillis(200)))
                .isInstanceOf(HttpTimeoutException.class);
    }

    @Test
    void attachesTheRequestAsTheClientWroteItAndTheResponseCompletedByTheBodyAsRead() throws Exception {
        ProtocolHttpResponse response = transport().send(new ProtocolHttpRequest(uri("/mcp"), "POST",
                Map.of("Authorization", "Bearer real-token", "Content-Type", "application/json"), "{}"), TIMEOUT);
        byte[] body;
        try (InputStream read = response.body()) {
            body = read.readAllBytes();
        }

        String request = text(response.wire().orElseThrow().evidence().request().toByteArray().getBytes());
        String reply = text(response.wire().orElseThrow().withBodyAsRead(body, false).evidence().response()
                .toByteArray().getBytes());

        assertThat(request).startsWith("POST /mcp HTTP/1.1\r\nContent-Length: 2\r\nHost: 127.0.0.1:")
                .contains("\r\nUser-Agent: Java-http-client/", "\r\nAuthorization: Bearer real-token\r\n")
                .endsWith("\r\n\r\n{}");
        assertThat(reply).startsWith("HTTP/1.1 201 Created\r\n")
                .contains("\r\nx-multi: one\r\nx-multi: two\r\n", "content-length: 7\r\n")
                .endsWith("\r\n\r\necho:{}");
    }

    private static String text(byte[] bytes) {
        return new String(bytes, StandardCharsets.ISO_8859_1);
    }

    private JdkProtocolHttpTransport transport() {
        return new JdkProtocolHttpTransport(client);
    }

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path);
    }

    private void echo(HttpExchange exchange) throws IOException {
        receivedMethod = exchange.getRequestMethod();
        receivedSessionHeader = exchange.getRequestHeaders().getFirst("Mcp-Session-Id");
        receivedContentType = exchange.getRequestHeaders().getFirst("Content-Type");
        receivedBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("X-Multi", "one");
        exchange.getResponseHeaders().add("X-Multi", "two");
        respond(exchange, 201, "Mcp-Session-Id", "server-session", "echo:" + receivedBody);
    }

    private void stall(HttpExchange exchange) throws IOException {
        try {
            releaseStalled.await(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        respond(exchange, 200, "Content-Type", "application/json", "{}");
    }

    private static void respond(HttpExchange exchange, int status, String headerName, String headerValue,
                                String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add(headerName, headerValue);
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
