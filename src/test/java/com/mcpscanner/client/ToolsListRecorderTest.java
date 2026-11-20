package com.mcpscanner.client;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.http.evidence.WireRecord;
import com.mcpscanner.mcp.BoundedBodyReader;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ToolsListRecorderTest {

    private static final URI ENDPOINT = URI.create("http://127.0.0.1:9/mcp");
    private static final String TOOLS_LIST = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}";
    private static final String RAW_REQUEST = "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:9\r\n"
            + "Authorization: Bearer invalid_x\r\nContent-Length: " + TOOLS_LIST.length() + "\r\n\r\n" + TOOLS_LIST;
    private static final String TOOLS = "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"list_users\"}]}}";

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void recordsTheFirstToolsListExchangeAndStillHandsTheReplyToTheCaller() throws Exception {
        ToolsListRecorder recorder = new ToolsListRecorder((request, timeout) -> reply(TOOLS));

        try (ProtocolHttpResponse response = recorder.send(post(TOOLS_LIST), Duration.ofSeconds(1))) {
            assertThat(BoundedBodyReader.readUtf8(response.body())).isEqualTo(TOOLS);
        }
        HttpRequestResponse recorded = recorder.recorded().orElseThrow();
        assertThat(text(recorded.request().toByteArray().getBytes())).isEqualTo(RAW_REQUEST);
        assertThat(text(recorded.response().toByteArray().getBytes())).isEqualTo(rawReply(TOOLS));
    }

    @Test
    void leavesTheBodyUnreadSoTheProtocolReaderStopsAtTheReply() throws Exception {
        byte[] reply = ("event: message\ndata: " + TOOLS + "\n\n").getBytes(StandardCharsets.UTF_8);
        ToolsListRecorder recorder = new ToolsListRecorder((request, timeout) -> new ProtocolHttpResponse(200,
                Map.of("Content-Type", List.of("text/event-stream")), new HeldOpenStream(reply), ENDPOINT,
                Optional.of(jdkWire(200, "content-type", "text/event-stream"))));

        ProtocolHttpResponse response = assertTimeoutPreemptively(Duration.ofSeconds(5),
                () -> recorder.send(post(TOOLS_LIST), Duration.ofSeconds(1)));
        try (response) {
            assertThat(response.body().readNBytes(reply.length)).isEqualTo(reply);
        }

        assertThat(recorder.recorded()).hasValueSatisfying(exchange ->
                assertThat(text(exchange.response().toByteArray().getBytes()))
                        .isEqualTo("HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n"
                                + new String(reply, StandardCharsets.UTF_8)));
    }

    @Test
    void attachesNoEvidenceWhenTheReplyHasNoBody() throws Exception {
        ToolsListRecorder recorder = new ToolsListRecorder((request, timeout) -> new ProtocolHttpResponse(202,
                Map.of(), InputStream.nullInputStream(), ENDPOINT, Optional.of(jdkWire(202))));

        try (ProtocolHttpResponse response = recorder.send(post(TOOLS_LIST), Duration.ofSeconds(1))) {
            assertThat(response.body().readAllBytes()).isEmpty();
        }

        assertThat(recorder.recorded()).isEmpty();
    }

    @Test
    void ignoresEveryOtherMethod() throws Exception {
        ToolsListRecorder recorder = new ToolsListRecorder((request, timeout) -> reply("{}"));

        recorder.send(post("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}"), Duration.ofSeconds(1));
        recorder.send(new ProtocolHttpRequest(ENDPOINT, "GET", Map.of(), null), Duration.ofSeconds(1));

        assertThat(recorder.recorded()).isEmpty();
    }

    private static final class HeldOpenStream extends InputStream {
        private final ByteArrayInputStream reply;
        private final CountDownLatch closed = new CountDownLatch(1);

        HeldOpenStream(byte[] reply) {
            this.reply = new ByteArrayInputStream(reply);
        }

        @Override
        public int read() throws IOException {
            if (reply.available() > 0) {
                return reply.read();
            }
            try {
                closed.await();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            throw new IOException("closed");
        }

        @Override
        public void close() {
            closed.countDown();
        }
    }

    private static ProtocolHttpRequest post(String body) {
        return new ProtocolHttpRequest(ENDPOINT, "POST", Map.of("Authorization", "Bearer invalid_x"), body);
    }

    private static ProtocolHttpResponse reply(String body) {
        return new ProtocolHttpResponse(200, Map.of("Content-Type", List.of("application/json")),
                new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)), ENDPOINT,
                Optional.of(wire(rawReply(body))));
    }

    private static String rawReply(String body) {
        return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + body.length()
                + "\r\n\r\n" + body;
    }

    @SuppressWarnings("unchecked")
    private static WireRecord jdkWire(int status, String... header) {
        java.net.http.HttpResponse<InputStream> head = mock(java.net.http.HttpResponse.class);
        when(head.statusCode()).thenReturn(status);
        when(head.version()).thenReturn(java.net.http.HttpClient.Version.HTTP_1_1);
        when(head.headers()).thenReturn(java.net.http.HttpHeaders.of(
                header.length == 0 ? Map.of() : Map.of(header[0], List.of(header[1])), (name, value) -> true));
        java.net.http.HttpRequest sent = java.net.http.HttpRequest.newBuilder(ENDPOINT)
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(TOOLS_LIST)).build();
        return WireRecord.ofJdk(sent, TOOLS_LIST.getBytes(StandardCharsets.UTF_8), head);
    }

    private static WireRecord wire(String rawResponse) {
        return WireRecord.ofBurp(HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequest(HttpService.httpService("127.0.0.1", 9, false),
                        ByteArray.byteArray(RAW_REQUEST.getBytes(StandardCharsets.ISO_8859_1))),
                HttpResponse.httpResponse(ByteArray.byteArray(rawResponse.getBytes(StandardCharsets.ISO_8859_1)))));
    }

    private static String text(byte[] bytes) {
        return new String(bytes, StandardCharsets.ISO_8859_1);
    }
}
