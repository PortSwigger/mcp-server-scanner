package com.mcpscanner.auth.oauth.discovery;

import com.mcpscanner.testutil.ClosedPort;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class DirectStreamGetChallengeSenderTest {

    private final DirectStreamGetChallengeSender sender = new DirectStreamGetChallengeSender();
    private final CountDownLatch streamEnded = new CountDownLatch(1);
    private final ExecutorService handlers = Executors.newCachedThreadPool();
    private HttpServer server;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(handlers);
        server.createContext("/protected", this::challenge);
        server.createContext("/stream", this::openStream);
        server.start();
    }

    @AfterEach
    void stopServer() {
        streamEnded.countDown();
        server.stop(0);
        handlers.shutdownNow();
    }

    @Test
    void aChallengeIsReadFromTheDirectReply() {
        assertThat(sender.send(endpoint("/protected")))
                .contains(new ChallengeResponse(401, Optional.of("Bearer realm=\"mcp\"")));
    }

    @Test
    void anOpenEventStreamIsAnsweredWithoutWaitingForItToEnd() {
        Optional<ChallengeResponse> reply = assertTimeoutPreemptively(Duration.ofSeconds(4),
                () -> sender.send(endpoint("/stream")));

        assertThat(reply).contains(new ChallengeResponse(200, Optional.empty()));
    }

    @Test
    void anUnreachableServerIsUnanswered() throws IOException {
        assertThat(sender.send(URI.create("http://127.0.0.1:" + ClosedPort.onLoopback() + "/mcp"))).isEmpty();
    }

    private URI endpoint(String path) {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path);
    }

    private void challenge(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().add("WWW-Authenticate", "Bearer realm=\"mcp\"");
        exchange.sendResponseHeaders(401, -1);
        exchange.close();
    }

    private void openStream(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", "text/event-stream");
        exchange.sendResponseHeaders(200, 0);
        OutputStream body = exchange.getResponseBody();
        body.write(": open\n\n".getBytes(StandardCharsets.UTF_8));
        body.flush();
        awaitStreamEnd();
        exchange.close();
    }

    private void awaitStreamEnd() {
        try {
            streamEnded.await(30, TimeUnit.SECONDS);
        } catch (InterruptedException stopped) {
            Thread.currentThread().interrupt();
        }
    }
}
