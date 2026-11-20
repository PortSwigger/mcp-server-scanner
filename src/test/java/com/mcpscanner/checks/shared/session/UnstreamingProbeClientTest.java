package com.mcpscanner.checks.shared.session;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.shared.jsonrpc.McpReply;
import com.mcpscanner.http.wire.OneConnectionServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class UnstreamingProbeClientTest {

    private static final String PING = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}";
    private static final String ANSWER = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
    private static final String EVENTS = "event: message\ndata: " + ANSWER + "\n\n";
    private static final String EVENT_STREAM_REPLY = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
            + "Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n" + EVENTS;

    private final UnstreamingProbeClient client = new UnstreamingProbeClient(Duration.ofMillis(500));

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void theEvidenceRequestIsWhatTheJdkClientWroteWithTheCredential() throws Exception {
        try (OneConnectionServer server = OneConnectionServer.replyingWith(EVENT_STREAM_REPLY)) {
            HttpRequestResponse exchange = client.send(ping(server.port())).orElseThrow();

            assertThat(text(exchange.request().toByteArray().getBytes()))
                    .isEqualTo(server.received().head() + PING)
                    .contains("\r\nAuthorization: Bearer kept\r\n", "\r\nContent-Length: " + PING.length() + "\r\n",
                            "\r\nUser-Agent: Java-http-client/")
                    .doesNotContain("X-Mcp-Scanner-");
        }
    }

    @Test
    void theEvidenceResponseKeepsTheRawEventStreamAndEveryHeaderLine() throws Exception {
        try (OneConnectionServer server = OneConnectionServer.replyingWith(EVENT_STREAM_REPLY)) {
            HttpRequestResponse exchange = client.send(ping(server.port())).orElseThrow();

            assertThat(text(exchange.response().toByteArray().getBytes()))
                    .startsWith("HTTP/1.1 200 OK\r\n")
                    .contains("\r\nset-cookie: a=1\r\nset-cookie: b=2\r\n", "\r\ncontent-type: text/event-stream\r\n")
                    .doesNotContain("application/json", "ontent-length")
                    .endsWith("\r\n\r\n" + EVENTS);
            assertThat(McpReply.answering(exchange, McpReply::isResponse).answered()).isTrue();
        }
    }

    @Test
    void anUnansweredProbeKeepsTheRequestTheJdkClientWrote() throws Exception {
        try (OneConnectionServer server = OneConnectionServer.silent()) {
            HttpRequestResponse exchange = client.send(ping(server.port())).orElseThrow();

            assertThat(exchange.response()).isNull();
            assertThat(text(exchange.request().toByteArray().getBytes()))
                    .isEqualTo(server.received().head() + PING);
        }
    }

    private static HttpRequest ping(int port) {
        return HttpRequest.httpRequestFromUrl("http://127.0.0.1:" + port + "/mcp").withMethod("POST")
                .withHeader("Authorization", "Bearer kept").withHeader("Content-Type", "application/json")
                .withBody(PING);
    }

    private static String text(byte[] bytes) {
        return new String(bytes, StandardCharsets.ISO_8859_1);
    }
}
