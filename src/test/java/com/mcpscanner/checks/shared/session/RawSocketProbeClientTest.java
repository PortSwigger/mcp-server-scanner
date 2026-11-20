package com.mcpscanner.checks.shared.session;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.shared.jsonrpc.McpReply;
import com.mcpscanner.http.wire.OneConnectionServer;
import com.mcpscanner.http.wire.SocketHttpTransport;
import com.mcpscanner.testutil.ClosedPort;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RawSocketProbeClientTest {

    private static final String PING = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}";
    private static final String ANSWER = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
    private static final String EVENT_STREAM_REPLY = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
            + "X-Served-By: stream\r\n\r\nevent: message\ndata: " + ANSWER + "\n\n";

    private final RawSocketProbeClient client = new RawSocketProbeClient(Duration.ofMillis(500));

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void sendsAHostHeaderNamingAnotherHostVerbatim() throws Exception {
        try (OneConnectionServer server = OneConnectionServer.replyingWith(EVENT_STREAM_REPLY)) {
            client.send(ping(server.port()).withHeader("Host", "attacker.example"));

            assertThat(server.received().head()).contains("\r\nHost: attacker.example\r\n");
        }
    }

    @Test
    void theEvidenceRequestIsTheBytesTheServerReceivedWithItsCredential() throws Exception {
        try (OneConnectionServer server = OneConnectionServer.replyingWith(EVENT_STREAM_REPLY)) {
            HttpRequestResponse exchange = client.send(ping(server.port()).withHeader("Host", "attacker.example")
                    .withHeader("Authorization", "Bearer kept")).orElseThrow();

            assertThat(text(exchange.request().toByteArray().getBytes()))
                    .isEqualTo(server.received().head() + PING)
                    .contains("\r\nAuthorization: Bearer kept\r\n", "\r\nContent-Length: " + PING.length() + "\r\n",
                            "\r\nConnection: close\r\n")
                    .doesNotContain("X-Mcp-Scanner-");
        }
    }

    @Test
    void theEvidenceResponseIsTheEventStreamExactlyAsReceived() throws Exception {
        try (OneConnectionServer server = OneConnectionServer.replyingWith(EVENT_STREAM_REPLY)) {
            HttpRequestResponse exchange = client.send(ping(server.port())).orElseThrow();

            assertThat(text(exchange.response().toByteArray().getBytes())).isEqualTo(EVENT_STREAM_REPLY);
            assertThat(McpReply.answering(exchange, McpReply::isResponse).answered()).isTrue();
        }
    }

    @Test
    void aChunkedReplyKeepsItsFramingAndRepeatedHeadersAndStillAnswersTheProbe() throws Exception {
        String event = "event: message\r\ndata: " + ANSWER + "\r\n\r\n";
        String chunked = "HTTP/1.1 200 Fine\r\nContent-Type: text/event-stream\r\nSet-Cookie: a=1\r\n"
                + "Set-Cookie: b=2\r\nTransfer-Encoding: chunked\r\n\r\n"
                + Integer.toHexString(event.length()) + "\r\n" + event + "\r\n0\r\n\r\n";
        try (OneConnectionServer server = OneConnectionServer.replyingWith(chunked)) {
            HttpRequestResponse exchange = client.send(ping(server.port())).orElseThrow();

            assertThat(text(exchange.response().toByteArray().getBytes())).startsWith(chunked.substring(0,
                    chunked.indexOf("\r\n\r\n") + 4) + Integer.toHexString(event.length()) + "\r\n" + event);
            assertThat(McpReply.answering(exchange, McpReply::isResponse).answered()).isTrue();
        }
    }

    @Test
    void aChunkedJsonReplyKeepsItsFramingAndStillAnswersTheProbe() throws Exception {
        String chunked = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
                + Integer.toHexString(ANSWER.length()) + "\r\n" + ANSWER + "\r\n0\r\n\r\n";
        try (OneConnectionServer server = OneConnectionServer.replyingWith(chunked)) {
            HttpRequestResponse exchange = client.send(ping(server.port())).orElseThrow();

            assertThat(text(exchange.response().toByteArray().getBytes())).isEqualTo(chunked);
            assertThat(McpReply.answering(exchange, McpReply::isResponse).answered()).isTrue();
        }
    }

    @Test
    void aProbeTheServerNeverAnswersWasSentWithoutAResponse() throws Exception {
        try (OneConnectionServer server = OneConnectionServer.silent()) {
            Optional<HttpRequestResponse> exchange = client.send(ping(server.port()));

            assertThat(exchange).hasValueSatisfying(sent -> {
                assertThat(sent.response()).isNull();
                assertThat(text(sent.request().toByteArray().getBytes())).startsWith("POST /mcp HTTP/1.1\r\n")
                        .contains("\r\nConnection: close\r\n").endsWith(PING);
            });
        }
    }

    @Test
    void aProbeThatCouldNotConnectWasNotSent() throws IOException {
        assertThat(client.send(ping(ClosedPort.onLoopback()))).isEmpty();
    }

    @Test
    void aProbeToAnUnusableServiceWasNotSentRatherThanThrown() {
        HttpRequest unusablePort = ping(1).withService(HttpService.httpService("127.0.0.1", 70_000, false));

        assertThat(client.send(unusablePort)).isEmpty();
    }

    @Test
    void aReplyThatFailsToParseAtRuntimeWasSentWithoutAResponseRatherThanThrown() throws Exception {
        ProbeReplyReader failingReader = mock(ProbeReplyReader.class);
        doThrow(new IllegalStateException("unparsable")).when(failingReader).awaitReply(any(), any(), any());
        RawSocketProbeClient failingClient = new RawSocketProbeClient(
                new SocketHttpTransport(Duration.ofMillis(500)), failingReader);
        try (OneConnectionServer server = OneConnectionServer.replyingWith(EVENT_STREAM_REPLY)) {
            Optional<HttpRequestResponse> exchange = failingClient.send(ping(server.port()));

            assertThat(exchange).hasValueSatisfying(sent -> assertThat(sent.response()).isNull());
        }
    }

    private static String text(byte[] bytes) {
        return new String(bytes, StandardCharsets.ISO_8859_1);
    }

    private static HttpRequest ping(int port) {
        return HttpRequest.httpRequestFromUrl("http://127.0.0.1:" + port + "/mcp").withMethod("POST")
                .withBody(PING);
    }
}
