package com.mcpscanner.http.evidence;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class WireRecordTest {

    private static final String BURP_REQUEST = "POST /mcp HTTP/1.1\r\nHost: upstream.test\r\n"
            + "Authorization: Bearer real\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
    private static final String CHUNKED_REPLY = "HTTP/1.1 200 Fine Thanks\r\nTransfer-Encoding: chunked\r\n"
            + "Set-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n2\r\nok\r\n0\r\n\r\n";
    private static final String JSON = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}";

    private LoopbackWireCapture wire;

    @BeforeEach
    void setUp() throws Exception {
        MontoyaTestFactory.install();
        wire = new LoopbackWireCapture();
    }

    @AfterEach
    void closeLoopback() throws Exception {
        wire.close();
    }

    @Test
    void burpsExchangeIsKeptExactlyAsBurpSentAndReceivedIt() {
        WireRecord record = WireRecord.ofBurp(burpExchange());

        HttpRequestResponse evidence = record.evidence();

        assertThat(text(evidence.request().toByteArray())).isEqualTo(BURP_REQUEST);
        assertThat(text(evidence.response().toByteArray())).isEqualTo(CHUNKED_REPLY);
        assertThat(evidence.request().httpService().host()).isEqualTo("upstream.test");
    }

    @Test
    void aBurpRecordKeepsItsRawBodyWhateverTheCallerRead() {
        WireRecord record = WireRecord.ofBurp(burpExchange()).withBodyAsRead(bytes("ok"), false);

        assertThat(text(record.evidence().response().toByteArray())).isEqualTo(CHUNKED_REPLY);
    }

    @Test
    void aJdkRecordIsTheRenderedRequestAndTheResponseHeadFollowedByTheBodyAsRead() throws Exception {
        java.net.http.HttpRequest post = java.net.http.HttpRequest.newBuilder(wire.uri("/mcp"))
                .timeout(Duration.ofSeconds(10)).header("Authorization", "Bearer real")
                .method("POST", java.net.http.HttpRequest.BodyPublishers.ofString(JSON)).build();
        LoopbackWireCapture.Captured captured = wire.send(post,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\nok");

        WireRecord record = WireRecord.ofJdk(post, bytes(JSON), captured.response()).withBodyAsRead(bytes("ok"), false);
        HttpRequestResponse evidence = record.evidence();

        assertThat(evidence.request().toByteArray().getBytes()).isEqualTo(captured.received());
        assertThat(text(evidence.response().toByteArray()))
                .isEqualTo("HTTP/1.1 200 OK\r\ncontent-length: 2\r\ncontent-type: application/json\r\n\r\nok");
        assertThat(evidence.request().httpService().port()).isEqualTo(wire.uri("/").getPort());
        assertThat(record.size()).isEqualTo(captured.received().length + evidence.response().toByteArray().length());
    }

    @Test
    void aLegacySseExchangeIsThePostWithItsOwnReplyThenTheStreamsGetWithTheRawEventThatAnswered() throws Exception {
        java.net.http.HttpRequest post = java.net.http.HttpRequest.newBuilder(wire.uri("/messages"))
                .timeout(Duration.ofSeconds(10))
                .method("POST", java.net.http.HttpRequest.BodyPublishers.ofString(JSON)).build();
        LoopbackWireCapture.Captured posted = wire.send(post, "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n");
        LoopbackWireCapture.Captured stream = wire.send(java.net.http.HttpRequest.newBuilder(wire.uri("/sse"))
                .timeout(Duration.ofSeconds(10)).GET().build(),
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n");
        String event = "id: 3\r\ndata: {\"a\":\r\ndata: 1}\r\n\r\n";

        List<HttpRequestResponse> evidence = LegacySseExchange.answered(
                WireRecord.ofJdk(post, bytes(JSON), posted.response()).withBody(new byte[0], false),
                stream.response(), bytes(event)).stream().map(WireRecord::evidence).toList();

        assertThat(evidence).hasSize(2);
        assertThat(evidence.get(0).request().toByteArray().getBytes()).isEqualTo(posted.received());
        assertThat(text(evidence.get(0).response().toByteArray()))
                .isEqualTo("HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\n\r\n");
        assertThat(evidence.get(1).request().toByteArray().getBytes()).isEqualTo(stream.received());
        assertThat(text(evidence.get(1).response().toByteArray())).isEqualTo("HTTP/1.1 200 OK\r\nconnection: close\r\n"
                + "content-type: text/event-stream\r\n\r\n" + event);
    }

    @Test
    void aStreamEventIsTheGetThatOpenedTheStreamWithItsHeadAndTheRawEventAsBody() throws Exception {
        LoopbackWireCapture.Captured stream = wire.send(java.net.http.HttpRequest.newBuilder(wire.uri("/sse"))
                .timeout(Duration.ofSeconds(10)).GET().build(),
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n");
        String event = "event: message\r\ndata: {}\r\n\r\n";

        HttpRequestResponse evidence = WireRecord.streamEvent(stream.response(), bytes(event)).evidence();

        assertThat(evidence.request().toByteArray().getBytes()).isEqualTo(stream.received());
        assertThat(evidence.response().bodyToString()).isEqualTo(event);
    }

    @Test
    void aTruncatedBodyCarriesANoteSayingWhereTheScannerCutIt() {
        WireRecord record = WireRecord.ofBurp(burpExchange()).withBody(bytes("abc"), true);

        HttpRequestResponse evidence = record.evidence();

        assertThat(evidence.annotations().notes())
                .isEqualTo("Response body truncated at 3 bytes by the scanner's size cap");
    }

    @Test
    void aCompleteBodyCarriesNoNote() {
        assertThat(WireRecord.ofBurp(burpExchange()).evidence().annotations().hasNotes()).isFalse();
    }

    @Test
    void withBodyReplacesTheBodyAfterTheResponseHead() {
        WireRecord record = WireRecord.ofBurp(burpExchange()).withBody(bytes("event: message\n\n"), false);

        assertThat(text(record.evidence().response().toByteArray())).isEqualTo("HTTP/1.1 200 Fine Thanks\r\n"
                + "Transfer-Encoding: chunked\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\nevent: message\n\n");
    }

    @Test
    void aSocketRecordIsTheBytesWrittenAndTheBytesReadExactly() {
        String written = "POST /mcp HTTP/1.1\r\nHost: attacker.example\r\nAuthorization: Bearer real\r\n"
                + "Connection: close\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
        HttpService service = HttpService.httpService("127.0.0.1", 8080, false);

        HttpRequestResponse evidence = WireRecord.ofSocket(service, bytes(written), bytes(CHUNKED_REPLY), false)
                .evidence();

        assertThat(text(evidence.request().toByteArray())).isEqualTo(written);
        assertThat(text(evidence.response().toByteArray())).isEqualTo(CHUNKED_REPLY);
        assertThat(evidence.request().httpService().port()).isEqualTo(8080);
        assertThat(evidence.annotations().hasNotes()).isFalse();
    }

    @Test
    void aSocketRecordReportsTheFinalResponseAfterInterimOnes() {
        HttpService service = HttpService.httpService("127.0.0.1", 8080, false);
        String finalResponse = "HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"a\":1}";
        String read = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n"
                + finalResponse;

        HttpRequestResponse evidence = WireRecord.ofSocket(service, bytes(BURP_REQUEST), bytes(read), false)
                .evidence();

        assertThat(evidence.response().statusCode()).isEqualTo((short) 200);
        assertThat(text(evidence.response().toByteArray())).isEqualTo(finalResponse);
    }

    @Test
    void aSocketRecordKeepsASwitchingProtocolsResponseAsFinal() {
        HttpService service = HttpService.httpService("127.0.0.1", 8080, false);
        String read = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n";

        HttpRequestResponse evidence = WireRecord.ofSocket(service, bytes(BURP_REQUEST), bytes(read), false)
                .evidence();

        assertThat(text(evidence.response().toByteArray())).isEqualTo(read);
    }

    @Test
    void aSocketRecordCutByTheCapSaysHowMuchBodyItKept() {
        HttpService service = HttpService.httpService("127.0.0.1", 8080, false);

        HttpRequestResponse evidence = WireRecord.ofSocket(service, bytes(BURP_REQUEST),
                bytes("HTTP/1.1 200 OK\r\n\r\nabcd"), true).evidence();

        assertThat(evidence.annotations().notes())
                .isEqualTo("Response body truncated at 4 bytes by the scanner's size cap");
    }

    @Test
    void anUnansweredRecordIsTheRequestAsWrittenWithNoResponse() {
        HttpService service = HttpService.httpService("127.0.0.1", 8080, false);

        HttpRequestResponse evidence = WireRecord.unanswered(service, bytes(BURP_REQUEST)).evidence();

        assertThat(text(evidence.request().toByteArray())).isEqualTo(BURP_REQUEST);
        assertThat(evidence.response()).isNull();
    }

    @Test
    void anUnansweredJdkRecordIsTheRequestAsTheJdkClientWroteIt() throws Exception {
        java.net.http.HttpRequest post = java.net.http.HttpRequest.newBuilder(wire.uri("/mcp"))
                .timeout(Duration.ofSeconds(10)).header("Authorization", "Bearer real")
                .method("POST", java.net.http.HttpRequest.BodyPublishers.ofString(JSON)).build();
        LoopbackWireCapture.Captured captured = wire.send(post, "HTTP/1.1 204 No Content\r\n\r\n");

        HttpRequestResponse evidence = WireRecord.unansweredJdk(post, bytes(JSON)).evidence();

        assertThat(evidence.request().toByteArray().getBytes()).isEqualTo(captured.received());
        assertThat(evidence.response()).isNull();
    }

    private static HttpRequestResponse burpExchange() {
        HttpService service = HttpService.httpService("upstream.test", 443, true);
        return HttpRequestResponse.httpRequestResponse(
                HttpRequest.httpRequest(service, ByteArray.byteArray(bytes(BURP_REQUEST))),
                HttpResponse.httpResponse(ByteArray.byteArray(bytes(CHUNKED_REPLY))));
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static String text(ByteArray bytes) {
        return new String(bytes.getBytes(), StandardCharsets.ISO_8859_1);
    }
}
