package com.mcpscanner.checks.shared.stream;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.http.wire.OneConnectionServer;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.ClosedPort;
import com.mcpscanner.testutil.ImmutableHttpRequest;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class JdkStreamOpenerTest {

    private static final StreamLimits FAST = new StreamLimits(Duration.ofSeconds(30), Duration.ofMillis(300), 64);

    private static final Duration CAP = Duration.ofSeconds(30);

    private final Map<String, String> received = new ConcurrentHashMap<>();
    private final CountDownLatch release = new CountDownLatch(1);
    private final CountDownLatch requestArrived = new CountDownLatch(1);
    private final CountDownLatch streamStarted = new CountDownLatch(1);
    private final CountDownLatch clientClosed = new CountDownLatch(1);
    private final McpEventLog log = new McpEventLog(null);
    private HttpServer server;

    @BeforeEach
    void setUp() throws IOException {
        MontoyaTestFactory.install();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/held", exchange -> stream(exchange, true));
        server.createContext("/closed", exchange -> stream(exchange, false));
        server.createContext("/refused", exchange -> respond(exchange, 401, "application/json", "{\"error\":\"no\"}"));
        server.createContext("/silent", exchange -> await());
        server.createContext("/flood", this::flood);
        server.createContext("/pinging", exchange -> pinging(exchange, Duration.ZERO));
        server.createContext("/slow-headers", exchange -> pinging(exchange, Duration.ofMillis(800)));
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.start();
    }

    @AfterEach
    void tearDown() {
        release.countDown();
        server.stop(0);
    }

    @Test
    void aStreamTheServerHoldsOpenIsOpenedWithItsStatusHeadersAndFirstBytes() {
        StreamOpening opening = new JdkStreamOpener(FAST).open(get("/held"));

        assertThat(opening.opened()).isTrue();
        assertThat(opening.status()).hasValue(200);
        assertThat(opening.exchange().response().headerValue("Content-Type")).startsWith("text/event-stream");
        assertThat(opening.exchange().response().bodyToString()).isEqualTo(": ready\n\n");
    }

    @Test
    void aStreamTheServerEndsAtOnceIsAnsweredButNotOpened() {
        StreamOpening opening = new JdkStreamOpener(FAST).open(get("/closed"));

        assertThat(opening.status()).hasValue(200);
        assertThat(opening.opened()).isFalse();
    }

    @Test
    void aRefusalIsRejectedWithItsBody() {
        StreamOpening opening = new JdkStreamOpener(FAST).open(get("/refused"));

        assertThat(opening.rejected()).isTrue();
        assertThat(opening.opened()).isFalse();
        assertThat(opening.exchange().response().bodyToString()).isEqualTo("{\"error\":\"no\"}");
    }

    @Test
    void aServerThatNeverAnswersIsUnansweredWithinTheHeaderTimeout() {
        StreamLimits quick = new StreamLimits(Duration.ofMillis(300), Duration.ofMillis(100), 64);

        StreamOpening opening = new JdkStreamOpener(quick).open(get("/silent"));

        assertThat(opening.answered()).isFalse();
        assertThat(opening.status()).isEmpty();
        assertThat(opening.exchange().request().url()).endsWith("/silent");
    }

    @Test
    void theReadStopsAtThePrefixLimitAndCountsTheStreamAsHeldOpen() {
        StreamOpening opening = new JdkStreamOpener(FAST).open(get("/flood"));

        assertThat(opening.opened()).isTrue();
        assertThat(opening.exchange().response().bodyToString()).hasSize(64);
    }

    @Test
    void anInterruptDuringTheHoldWindowClosesTheConnection() throws InterruptedException {
        StreamLimits longHold = new StreamLimits(Duration.ofSeconds(5), Duration.ofSeconds(10), 1 << 20);

        Thread caller = openInBackground(longHold, "/pinging", () -> holdingTheStream(callerThread()));

        assertThat(caller.isAlive()).isFalse();
        assertThat(interruptedAfterReturn).isTrue();
        assertThat(clientClosed.await(CAP.toSeconds(), TimeUnit.SECONDS)).as("server saw the connection close").isTrue();
    }

    @Test
    void anInterruptWhileWaitingForHeadersClosesTheConnectionWhenTheyArrive() throws InterruptedException {
        StreamLimits longHold = new StreamLimits(Duration.ofSeconds(5), Duration.ofSeconds(10), 1 << 20);

        Thread caller = openInBackground(longHold, "/slow-headers", () -> requestArrived.getCount() == 0);

        assertThat(caller.isAlive()).isFalse();
        assertThat(clientClosed.await(CAP.toSeconds(), TimeUnit.SECONDS)).as("server saw the connection close").isTrue();
    }

    @Test
    void aHeaderTimeoutClosesTheConnectionWhenTheHeadersArriveLater() throws InterruptedException {
        StreamLimits shortHeaderWait = new StreamLimits(Duration.ofMillis(100), Duration.ofSeconds(10), 1 << 20);

        StreamOpening opening = new JdkStreamOpener(shortHeaderWait).open(get("/slow-headers"));

        assertThat(opening.answered()).isFalse();
        assertThat(clientClosed.await(CAP.toSeconds(), TimeUnit.SECONDS)).as("server saw the connection close").isTrue();
    }

    @Test
    void aTlsFailureIsUnansweredAndWarnsThatBurpsNetworkSettingsDoNotApply() {
        String plainPortAsHttps = "https://127.0.0.1:" + server.getAddress().getPort() + "/held";

        StreamOpening opening = new JdkStreamOpener(FAST, log).open(StreamGetRequest.from(
                ImmutableHttpRequest.post(plainPortAsHttps, Map.of(), "{}"), java.util.Optional.empty()));

        assertThat(opening.answered()).isFalse();
        assertThat(warnings()).singleElement().asString()
                .contains("127.0.0.1", "client TLS certificates", "upstream proxy");
    }

    @Test
    void aRequestTheJdkClientRefusesToBuildIsNeitherSentNorAnswered() {
        StreamOpening opening = new JdkStreamOpener(FAST, log).open(get("/held").withMethod("CONNECT"));

        assertThat(opening.sent()).isFalse();
        assertThat(opening.answered()).isFalse();
        assertThat(received).isEmpty();
    }

    @Test
    void aStreamThatReachedTheServerCountsAsSent() {
        assertThat(new JdkStreamOpener(FAST).open(get("/held")).sent()).isTrue();
    }

    @Test
    void aRefusedConnectionWarnsOncePerOrigin() throws IOException {
        int closedPort = ClosedPort.onLoopback();
        JdkStreamOpener opener = new JdkStreamOpener(FAST, log);
        HttpRequest request = StreamGetRequest.from(ImmutableHttpRequest.post(
                "http://127.0.0.1:" + closedPort + "/mcp", Map.of(), "{}"), java.util.Optional.empty());

        opener.open(request);
        opener.open(request);

        assertThat(warnings()).hasSize(1);
    }

    @Test
    void scannerSentinelsNeverReachTheServerOrTheEvidence() {
        HttpRequest request = get("/held")
                .withHeader(ScannerSentinels.DIRECT_DELIVERY_HEADER, ScannerSentinels.SENTINEL_VALUE)
                .withHeader(ScannerSentinels.STRIP_AUTH_HEADER, ScannerSentinels.SENTINEL_VALUE)
                .withHeader("Authorization", "Bearer kept");

        StreamOpening opening = new JdkStreamOpener(FAST).open(request);

        assertThat(received).containsEntry("authorization", "Bearer kept")
                .doesNotContainKeys("x-mcp-scanner-direct", "x-mcp-scanner-strip-auth");
        assertThat(opening.exchange().request().hasHeader(ScannerSentinels.DIRECT_DELIVERY_HEADER)).isFalse();
        assertThat(opening.exchange().request().hasHeader("Authorization")).isTrue();
    }

    @Test
    void theEvidenceIsTheRequestTheJdkClientWroteAndTheStreamExactlyAsReceived() throws Exception {
        String head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n";
        String events = "event: endpoint\r\ndata: /messages?id=1\r\n\r\n";
        try (OneConnectionServer raw = OneConnectionServer.replyingWith(head + events)) {
            HttpRequest request = StreamGetRequest.from(ImmutableHttpRequest.post(
                    "http://127.0.0.1:" + raw.port() + "/sse", Map.of("Authorization", "Bearer kept"), "{}"),
                    java.util.Optional.empty()).withHeader(ScannerSentinels.STRIP_AUTH_HEADER, "1");

            StreamOpening opening = new JdkStreamOpener(FAST).open(request);

            assertThat(text(opening.exchange().request().toByteArray().getBytes()))
                    .isEqualTo(raw.received().head())
                    .contains("\r\nAuthorization: Bearer kept\r\n", "\r\nUser-Agent: Java-http-client/")
                    .doesNotContain("X-Mcp-Scanner-");
            assertThat(text(opening.exchange().response().toByteArray().getBytes()))
                    .startsWith("HTTP/1.1 200 OK\r\n")
                    .contains("\r\nset-cookie: a=1\r\nset-cookie: b=2\r\n")
                    .endsWith("\r\n\r\n" + events);
            assertThat(opening.exchange().annotations().hasNotes()).isFalse();
        }
    }

    @Test
    void aPrefixCutAtTheLimitIsFlaggedAsTruncated() {
        StreamOpening opening = new JdkStreamOpener(FAST).open(get("/flood"));

        assertThat(opening.exchange().annotations().notes())
                .isEqualTo("Response body truncated at 64 bytes by the scanner's size cap");
    }

    @Test
    void anUnansweredStreamKeepsTheRequestTheJdkClientWrote() {
        StreamLimits quick = new StreamLimits(Duration.ofMillis(300), Duration.ofMillis(100), 64);

        StreamOpening opening = new JdkStreamOpener(quick).open(get("/silent").withHeader("Authorization", "Bearer kept"));

        assertThat(text(opening.exchange().request().toByteArray().getBytes()))
                .startsWith("GET /silent HTTP/1.1\r\n")
                .contains("\r\nAuthorization: Bearer kept\r\n", "\r\nUser-Agent: Java-http-client/");
    }

    private static String text(byte[] bytes) {
        return new String(bytes, StandardCharsets.ISO_8859_1);
    }

    private volatile boolean interruptedAfterReturn;
    private volatile Thread caller;

    private Thread openInBackground(StreamLimits limits, String path, Callable<Boolean> interruptWhen)
            throws InterruptedException {
        caller = new Thread(() -> {
            new JdkStreamOpener(limits).open(get(path));
            interruptedAfterReturn = Thread.currentThread().isInterrupted();
        });
        caller.start();
        org.awaitility.Awaitility.await().atMost(CAP).until(interruptWhen);
        caller.interrupt();
        caller.join(CAP.toMillis());
        return caller;
    }

    private Thread callerThread() {
        return caller;
    }

    private static boolean holdingTheStream(Thread thread) {
        return thread != null && Arrays.stream(thread.getStackTrace()).anyMatch(frame ->
                frame.getClassName().equals(StreamPrefix.class.getName()) && frame.getMethodName().equals("await"));
    }

    private java.util.List<String> warnings() {
        return log.snapshot().stream().filter(entry -> entry.level() == McpEventLog.Level.WARN)
                .map(McpEventLog.LogEntry::message).toList();
    }

    private void pinging(HttpExchange exchange, Duration headerDelay) throws IOException {
        requestArrived.countDown();
        pause(headerDelay);
        exchange.getResponseHeaders().add("Content-Type", "text/event-stream");
        exchange.sendResponseHeaders(200, 0);
        OutputStream body = exchange.getResponseBody();
        streamStarted.countDown();
        try {
            while (release.getCount() > 0) {
                body.write(": ping\n\n".getBytes(StandardCharsets.UTF_8));
                body.flush();
                pause(Duration.ofMillis(50));
            }
        } catch (IOException closedByTheClient) {
            clientClosed.countDown();
        }
        exchange.close();
    }

    private static void pause(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private HttpRequest get(String path) {
        String url = "http://127.0.0.1:" + server.getAddress().getPort() + path;
        return StreamGetRequest.from(ImmutableHttpRequest.post(url, Map.of("Content-Type", "application/json"), "{}"),
                java.util.Optional.empty());
    }

    private void stream(HttpExchange exchange, boolean hold) throws IOException {
        exchange.getRequestHeaders().forEach((name, values) -> received.put(name.toLowerCase(), values.get(0)));
        exchange.getResponseHeaders().add("Content-Type", "text/event-stream");
        exchange.sendResponseHeaders(200, 0);
        OutputStream body = exchange.getResponseBody();
        body.write(": ready\n\n".getBytes(StandardCharsets.UTF_8));
        body.flush();
        if (hold) {
            await();
        }
        exchange.close();
    }

    private void flood(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", "text/event-stream");
        exchange.sendResponseHeaders(200, 0);
        try (OutputStream body = exchange.getResponseBody()) {
            body.write(": ".concat("x".repeat(500)).concat("\n\n").getBytes(StandardCharsets.UTF_8));
            body.flush();
            await();
        } catch (IOException clientWentAway) {
            exchange.close();
        }
    }

    private static void respond(HttpExchange exchange, int status, String type, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", type);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private void await() {
        try {
            release.await(CAP.toSeconds(), TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
