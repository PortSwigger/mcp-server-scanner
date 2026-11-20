package com.mcpscanner.proxy;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.client.ProtocolHttpRequest;
import com.mcpscanner.client.ProtocolHttpResponse;
import com.mcpscanner.client.ProtocolHttpTransport;
import com.mcpscanner.http.evidence.WireRecord;
import com.mcpscanner.testutil.FakeMcpServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.ScriptedProtocolTransport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;

class UpstreamCapturesTest {

    private static final URI ENDPOINT = URI.create("https://upstream.test/mcp");
    private static final Duration TIMEOUT = Duration.ofSeconds(5);

    private final UpstreamCaptures captures = new UpstreamCaptures();
    private final ScriptedProtocolTransport upstream = new ScriptedProtocolTransport(UpstreamCapturesTest::echo);
    private final ProtocolHttpTransport recording = captures.recording(upstream);

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void aResponseWithoutAWireRecordIsNotRecorded() throws Exception {
        ProtocolHttpTransport unrecorded = captures.recording((request, timeout) ->
                FakeMcpServer.exchange(request, 200, Map.of(), "{}"));

        try (ForwardCapture capture = captures.open()) {
            read(unrecorded.send(post("{\"id\":1}"), TIMEOUT));

            assertThat(capture.chosenFor("{\"id\":1}")).isEmpty();
        }
    }

    @Test
    void sendsOutsideACaptureAreNotRecorded() throws Exception {
        String body = read(recording.send(post("{\"id\":1}"), TIMEOUT));

        try (ForwardCapture capture = captures.open()) {
            assertThat(capture.chosenFor("{\"id\":1}")).isEmpty();
        }
        assertThat(body).isEqualTo("{\"echo\":{\"id\":1}}");
    }

    @Test
    void recordsTheRequestAsSentAndTheResponseBodyTheCallerRead() throws Exception {
        try (ForwardCapture capture = captures.open()) {
            String body = read(recording.send(post("{\"id\":1}"), TIMEOUT));

            RecordedExchange recorded = capture.chosenFor("{\"id\":1}").orElseThrow();
            assertThat(body).isEqualTo("{\"echo\":{\"id\":1}}");
            assertThat(recorded.requestBody()).isEqualTo("{\"id\":1}");
            assertThat(text(recorded.evidence().get(0).request().toByteArray().getBytes()))
                    .isEqualTo(rawRequest(post("{\"id\":1}")));
            assertThat(text(recorded.evidence().get(0).response().toByteArray().getBytes()))
                    .isEqualTo(rawReply(post("{\"id\":1}")));
        }
    }

    @Test
    void choosesTheExchangeCarryingTheForwardedIdOverHandshakeAndCleanup() throws Exception {
        try (ForwardCapture capture = captures.open()) {
            send("{\"jsonrpc\":\"2.0\",\"id\":100,\"method\":\"initialize\"}");
            send("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}");
            send("{\"jsonrpc\":\"2.0\",\"id\":101,\"method\":\"tools/call\"}");
            read(recording.send(new ProtocolHttpRequest(ENDPOINT, "DELETE", Map.of(), null), TIMEOUT));

            assertThat(capture.chosenFor("{\"jsonrpc\":\"2.0\",\"id\":101,\"method\":\"tools/call\"}")
                    .orElseThrow().requestBody()).contains("\"id\":101");
        }
    }

    @Test
    void choosesTheLastMatchingSendWhenTheSameIdWasSentTwice() throws Exception {
        try (ForwardCapture capture = captures.open()) {
            send("{\"id\":101,\"attempt\":1}");
            send("{\"id\":101,\"attempt\":2}");

            assertThat(capture.chosenFor("{\"id\":101}").orElseThrow().requestBody()).contains("\"attempt\":2");
        }
    }

    @Test
    void choosesTheLastSendOfTheSameMethodForANotification() throws Exception {
        try (ForwardCapture capture = captures.open()) {
            send("{\"jsonrpc\":\"2.0\",\"id\":100,\"method\":\"initialize\"}");
            send("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"n\":1}}");
            read(recording.send(new ProtocolHttpRequest(ENDPOINT, "DELETE", Map.of(), null), TIMEOUT));

            assertThat(capture.chosenFor("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\"}")
                    .orElseThrow().requestBody()).contains("\"n\":1");
        }
    }

    @Test
    void fallsBackToTheLastSendWhenNothingMatches() throws Exception {
        try (ForwardCapture capture = captures.open()) {
            send("{\"id\":1}");
            send("{\"id\":2}");

            assertThat(capture.chosenFor("[{\"id\":3}]").orElseThrow().requestBody()).isEqualTo("{\"id\":2}");
        }
    }

    @Test
    void closingTheCaptureStopsRecordingOnThatThread() throws Exception {
        ForwardCapture closed = captures.open();
        closed.close();

        send("{\"id\":1}");

        assertThat(closed.chosenFor("{\"id\":1}")).isEmpty();
    }

    @Test
    void anotherThreadsSendsAreNotRecordedInThisCapture() throws Exception {
        try (ForwardCapture capture = captures.open()) {
            CompletableFuture.runAsync(() -> {
                try {
                    send("{\"id\":1}");
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }).join();

            assertThat(capture.chosenFor("{\"id\":1}")).isEmpty();
        }
    }

    @Test
    void explicitlyRecordedExchangesJoinTheCurrentCaptureOnly() {
        RecordedExchange posted = new RecordedExchange("{\"id\":5}", wireOf(post("{\"id\":5}")));
        captures.record(posted);

        try (ForwardCapture capture = captures.open()) {
            captures.record(posted);

            assertThat(capture.chosenFor("{\"id\":5}")).contains(posted);
        }
    }

    private static ProtocolHttpResponse echo(ProtocolHttpRequest request) {
        ProtocolHttpResponse scripted = FakeMcpServer.exchange(request, 200,
                Map.of("Content-Type", List.of("application/json")), echoed(request));
        return new ProtocolHttpResponse(scripted.status(), scripted.headers(), scripted.body(), scripted.uri(),
                Optional.of(wireOf(request)));
    }

    private static WireRecord wireOf(ProtocolHttpRequest request) {
        return WireRecord.ofBurp(HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequest(HttpService.httpService(ENDPOINT.getHost(), 443, true),
                        ByteArray.byteArray(rawRequest(request).getBytes(StandardCharsets.ISO_8859_1))),
                HttpResponse.httpResponse(ByteArray.byteArray(rawReply(request).getBytes(StandardCharsets.ISO_8859_1)))));
    }

    private static String rawRequest(ProtocolHttpRequest request) {
        String body = request.hasBody() ? request.body() : "";
        return request.method() + " /mcp HTTP/1.1\r\nHost: upstream.test\r\nAuthorization: Bearer injected\r\n"
                + "Content-Length: " + body.length() + "\r\n\r\n" + body;
    }

    private static String rawReply(ProtocolHttpRequest request) {
        return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Upstream: yes\r\n\r\n" + echoed(request);
    }

    private static String echoed(ProtocolHttpRequest request) {
        return "{\"echo\":" + request.body() + "}";
    }

    private static String text(byte[] bytes) {
        return new String(bytes, StandardCharsets.ISO_8859_1);
    }

    private void send(String body) throws Exception {
        read(recording.send(post(body), TIMEOUT));
    }

    private static ProtocolHttpRequest post(String body) {
        return new ProtocolHttpRequest(ENDPOINT, "POST", Map.of("Authorization", "Bearer injected"), body);
    }

    private static String read(ProtocolHttpResponse response) throws Exception {
        try (response) {
            return new String(response.body().readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
