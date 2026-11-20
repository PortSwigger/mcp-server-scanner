package com.mcpscanner.client;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.core.protocol.McpFlow;
import com.mcpscanner.core.protocol.McpRequests;
import com.mcpscanner.http.evidence.WireRecord;
import com.mcpscanner.mcp.RawSseFrame;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SseToolsListRecorderTest {

    private static final URI MESSAGE_URL = URI.create("http://127.0.0.1:9/messages?session=7");
    private static final SseStreamOpening OPENING = SseStreamOpenings.of("http://127.0.0.1:9/sse",
            Map.of("Authorization", "Bearer bob", "Accept", "text/event-stream"),
            Map.of("Content-Type", List.of("text/event-stream"), "Cache-Control", List.of("no-cache")));
    private static final SseStreamOpening REOPENED = SseStreamOpenings.of("http://127.0.0.1:9/sse?attempt=2",
            Map.of("Authorization", "Bearer refreshed", "Accept", "text/event-stream"),
            Map.of("Content-Type", List.of("text/event-stream")));
    private static final String TOOLS_REPLY_BYTES = "id: 41\r\nevent: message\r\n"
            + "data: {\"jsonrpc\":\"2.0\",\"id\":3,\r\ndata: \"result\":{\"tools\":[]}}\r\n\r\n";
    private static final RawSseFrame TOOLS_REPLY = frame(TOOLS_REPLY_BYTES);

    private final SseToolsListRecorder recorder = new SseToolsListRecorder();

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void recordsThePostAsSentAndAnsweredThenTheStreamHeadWithTheRawEventThatAnsweredIt() {
        McpRequests.Request request = request("tools/list", "3");
        recorder.messagePosted(OPENING, request, accepted(request));
        recorder.eventReceived(OPENING, TOOLS_REPLY);

        List<HttpRequestResponse> recorded = recorder.recorded();
        assertThat(recorded).hasSize(2);
        String post = text(recorded.get(0).request().toByteArray());
        assertThat(post).startsWith("POST /messages?session=7 HTTP/1.1\r\n")
                .contains("Authorization: Bearer bob\r\n", "Host: 127.0.0.1:9\r\n",
                        "Content-Length: " + request.body().length() + "\r\n", "User-Agent: Java-http-client/")
                .doesNotContainIgnoringCase("X-Mcp-Scanner-")
                .endsWith("\r\n\r\n" + request.body());
        assertThat(text(recorded.get(0).response().toByteArray()))
                .isEqualTo("HTTP/1.1 202 Accepted\r\nset-cookie: a=1\r\nset-cookie: b=2\r\n\r\nAccepted");
        String get = text(recorded.get(1).request().toByteArray());
        assertThat(get).startsWith("GET /sse HTTP/1.1\r\n")
                .contains("Authorization: Bearer bob\r\n", "Host: 127.0.0.1:9\r\n", "User-Agent: Java-http-client/")
                .endsWith("\r\n\r\n");
        assertThat(text(recorded.get(1).response().toByteArray())).isEqualTo("HTTP/1.1 200 OK\r\n"
                + "Cache-Control: no-cache\r\nContent-Type: text/event-stream\r\n\r\n" + TOOLS_REPLY_BYTES);
    }

    @Test
    void recordsNothingOnceStoppedEvenWhileTheStreamItWatchedStaysOpen() {
        recorder.stop();
        McpRequests.Request request = request("tools/list", "3");
        recorder.messagePosted(OPENING, request, accepted(request));
        recorder.eventReceived(OPENING, TOOLS_REPLY);

        assertThat(recorder.recorded()).isEmpty();
    }

    @Test
    void keepsOnlyTheEventWhoseIdMatchesAmongNotificationsAndOtherReplies() {
        recorder.messagePosted(OPENING, request("tools/list", "3"), accepted(request("tools/list", "3")));
        recorder.eventReceived(OPENING, event("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}"));
        recorder.eventReceived(OPENING, event("{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}"));
        recorder.eventReceived(OPENING, TOOLS_REPLY);

        assertThat(recorder.recorded()).last().satisfies(exchange ->
                assertThat(exchange.response().bodyToString()).isEqualTo(TOOLS_REPLY_BYTES));
    }

    @Test
    void correlatesAStringRequestId() {
        RawSseFrame reply = event("{\"jsonrpc\":\"2.0\",\"id\":\"list-1\",\"result\":{\"tools\":[]}}");
        McpRequests.Request request = request("tools/list", "\"list-1\"");
        recorder.messagePosted(OPENING, request, accepted(request));
        recorder.eventReceived(OPENING, event("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"));
        recorder.eventReceived(OPENING, reply);

        assertThat(recorder.recorded()).last().satisfies(exchange ->
                assertThat(exchange.response().body().getBytes()).endsWith(reply.bytes()));
    }

    @Test
    void recordsNothingWhenNoReplyArrives() {
        recorder.messagePosted(OPENING, request("tools/list", "3"), accepted(request("tools/list", "3")));
        recorder.eventReceived(OPENING, event("{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}"));

        assertThat(recorder.recorded()).isEmpty();
    }

    @Test
    void ignoresAMalformedFrameAndStillRecordsTheLaterReply() {
        recorder.messagePosted(OPENING, request("tools/list", "3"), accepted(request("tools/list", "3")));

        assertThatCode(() -> {
            recorder.eventReceived(OPENING, frame("event: message\ndata: {not json\n\n"));
            recorder.eventReceived(OPENING, frame("data: truncated"));
            recorder.eventReceived(OPENING, event("[1,2]"));
        }).doesNotThrowAnyException();
        recorder.eventReceived(OPENING, TOOLS_REPLY);

        assertThat(recorder.recorded()).hasSize(2);
    }

    @Test
    void recordsOnlyTheFirstToolsList() {
        RawSseFrame secondReply = event("{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{\"tools\":[]}}");
        recorder.messagePosted(OPENING, request("tools/list", "3"), accepted(request("tools/list", "3")));
        recorder.eventReceived(OPENING, TOOLS_REPLY);
        recorder.messagePosted(OPENING, request("tools/list", "4"), accepted(request("tools/list", "4")));
        recorder.eventReceived(OPENING, secondReply);

        assertThat(recorder.recorded()).hasSize(2).last().satisfies(exchange ->
                assertThat(exchange.response().bodyToString()).isEqualTo(TOOLS_REPLY_BYTES));
    }

    @Test
    void recordsTheRetriedPostAndItsStreamAfterAChallengedPost() {
        McpRequests.Request retried = request("tools/list", "3", "Bearer refreshed");
        recorder.messagePosted(OPENING, request("tools/list", "3", "Bearer bob"),
                challenged(request("tools/list", "3", "Bearer bob")));
        recorder.messagePosted(REOPENED, retried, accepted(retried));
        recorder.eventReceived(REOPENED, TOOLS_REPLY);

        List<HttpRequestResponse> recorded = recorder.recorded();
        assertThat(recorded).hasSize(2);
        assertThat(recorded.get(0).request().headerValue("Authorization")).isEqualTo("Bearer refreshed");
        assertThat(recorded.get(0).response().statusCode()).isEqualTo((short) 202);
        assertThat(recorded.get(1).request().pathWithoutQuery()).isEqualTo("/sse");
        assertThat(recorded.get(1).request().query()).isEqualTo("attempt=2");
        assertThat(recorded.get(1).response().bodyToString()).isEqualTo(TOOLS_REPLY_BYTES);
    }

    @Test
    void aToolsListPostedOnANewStreamSupersedesAnUnansweredOne() {
        McpRequests.Request retried = request("tools/list", "3", "Bearer refreshed");
        recorder.messagePosted(OPENING, request("tools/list", "3", "Bearer bob"),
                accepted(request("tools/list", "3", "Bearer bob")));
        recorder.messagePosted(REOPENED, retried, accepted(retried));
        recorder.eventReceived(REOPENED, TOOLS_REPLY);

        assertThat(recorder.recorded()).first().satisfies(post ->
                assertThat(post.request().headerValue("Authorization")).isEqualTo("Bearer refreshed"));
    }

    @Test
    void ignoresAReplyOnAnotherStreamThanThePendingPost() {
        recorder.messagePosted(OPENING, request("tools/list", "3"), accepted(request("tools/list", "3")));
        recorder.eventReceived(REOPENED, TOOLS_REPLY);

        assertThat(recorder.recorded()).isEmpty();
    }

    @Test
    void ignoresAChallengedPostEvenWhenItsIdIsAnswered() {
        recorder.messagePosted(OPENING, request("tools/list", "3"), challenged(request("tools/list", "3")));
        recorder.eventReceived(OPENING, TOOLS_REPLY);

        assertThat(recorder.recorded()).isEmpty();
    }

    @Test
    void ignoresAPostWithoutAWireRecord() {
        recorder.messagePosted(OPENING, request("tools/list", "3"), new SseMessagePost(
                new McpFlow.HttpResponse(202, Map.of(), "", true), Optional.empty()));
        recorder.eventReceived(OPENING, TOOLS_REPLY);

        assertThat(recorder.recorded()).isEmpty();
    }

    @Test
    void ignoresRepliesToOtherMethods() {
        recorder.messagePosted(OPENING, request("resources/list", "3"), accepted(request("resources/list", "3")));
        recorder.eventReceived(OPENING, TOOLS_REPLY);

        assertThat(recorder.recorded()).isEmpty();
    }

    @Test
    void ignoresAMalformedPostedBody() {
        McpRequests.Request malformed = new McpRequests.Request("{not json", Map.of());
        assertThatCode(() -> recorder.messagePosted(OPENING, malformed, accepted(malformed)))
                .doesNotThrowAnyException();
        recorder.eventReceived(OPENING, TOOLS_REPLY);

        assertThat(recorder.recorded()).isEmpty();
    }

    private static SseMessagePost accepted(McpRequests.Request request) {
        return posted(request, 202, Map.of("set-cookie", List.of("a=1", "b=2")), "Accepted");
    }

    private static SseMessagePost challenged(McpRequests.Request request) {
        return posted(request, 401, Map.of("www-authenticate", List.of("Bearer")), "");
    }

    @SuppressWarnings("unchecked")
    private static SseMessagePost posted(McpRequests.Request request, int status,
                                         Map<String, List<String>> headers, String body) {
        HttpRequest.Builder post = HttpRequest.newBuilder(MESSAGE_URL)
                .POST(HttpRequest.BodyPublishers.ofString(request.body()));
        request.headers().forEach(post::header);
        HttpResponse<Void> head = mock(HttpResponse.class);
        when(head.statusCode()).thenReturn(status);
        when(head.headers()).thenReturn(HttpHeaders.of(headers, (name, value) -> true));
        WireRecord wire = WireRecord.ofJdk(post.build(), request.body().getBytes(StandardCharsets.UTF_8), head)
                .withBody(body.getBytes(StandardCharsets.UTF_8), false);
        return new SseMessagePost(new McpFlow.HttpResponse(status, Map.of(), body, true), Optional.of(wire));
    }

    private static McpRequests.Request request(String method, String id) {
        return request(method, id, "Bearer bob");
    }

    private static McpRequests.Request request(String method, String id, String authorization) {
        return new McpRequests.Request("{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"method\":\"" + method + "\"}",
                Map.of("Authorization", authorization, "Content-Type", "application/json"));
    }

    private static RawSseFrame event(String data) {
        return frame("event: message\ndata: " + data + "\n\n");
    }

    private static RawSseFrame frame(String wire) {
        return new RawSseFrame(wire.replace("\r\n", "\n"), wire.getBytes(StandardCharsets.UTF_8));
    }

    private static String text(burp.api.montoya.core.ByteArray bytes) {
        return new String(bytes.getBytes(), java.nio.charset.StandardCharsets.ISO_8859_1);
    }
}
