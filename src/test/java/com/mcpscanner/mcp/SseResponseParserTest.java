package com.mcpscanner.mcp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

import org.junit.jupiter.api.Test;
import static com.mcpscanner.testutil.AwaitedFutures.valueWithin;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SseResponseParserTest {

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"", "\n"})
    void ignoresEndpointWithoutEventTerminator(String ending) throws Exception {
        String sse = "event: endpoint\ndata: /message" + ending;

        assertThat(endpointOf(sse)).isNull();
    }

    @Test
    void acceptsReplyTerminatedByMixedLineEndings() throws Exception {
        String response = "{\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{}}";
        String sse = "event: message\ndata: " + response + "\n\r";

        assertThat(SseResponseParser.extractJsonRpcResponse(sse)).isEqualTo(response);
        assertThat(SseResponseParser.extractJsonRpcResponse(
                new BufferedReader(new StringReader(sse)),
                SseResponseParser.expectedReplyId("{\"id\":42,\"method\":\"tools/list\"}")))
                .isEqualTo(response);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"\r", "\r\n", "\n\r"})
    void acceptsReplyWithValidEventLineEndings(String lineEnding) throws Exception {
        String response = "{\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{}}";
        String sse = "event: message" + lineEnding + "data: " + response + lineEnding + lineEnding;

        assertThat(SseResponseParser.extractJsonRpcResponse(sse)).isEqualTo(response);
        assertThat(SseResponseParser.extractJsonRpcResponse(
                new BufferedReader(new StringReader(sse)),
                SseResponseParser.expectedReplyId("{\"id\":42,\"method\":\"tools/list\"}")))
                .isEqualTo(response);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"", "\n"})
    void ignoresReplyWithoutEventTerminator(String ending) throws Exception {
        String sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{}}" + ending;

        assertThat(SseResponseParser.extractJsonRpcResponse(
                new BufferedReader(new StringReader(sse)))).isNull();
        assertThat(SseResponseParser.extractJsonRpcResponse(sse)).isNull();
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"", "\n"})
    void ignoresCorrelatedReplyWithoutEventTerminator(String ending) throws Exception {
        String response = "{\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{\"tools\":[]}}";

        String reply = SseResponseParser.extractJsonRpcResponse(
                new BufferedReader(new StringReader("event: message\ndata: " + response + ending)),
                SseResponseParser.expectedReplyId("{\"id\":42,\"method\":\"tools/list\"}"));

        assertThat(reply).isNull();
    }

    @Test
    void stopsUnrelatedEventStreamAtFiniteEventLimit() {
        String sse = "data: {}\n\n".repeat(4097);

        assertThatThrownBy(() -> SseResponseParser.extractJsonRpcResponse(
                new BufferedReader(new StringReader(sse)),
                SseResponseParser.expectedReplyId("{\"method\":\"tools/list\",\"id\":7}")))
                .isInstanceOf(IOException.class)
                .hasMessage("SSE response exceeded event limit");
    }

    @Test
    void stopsUnrelatedEventStreamAtAggregateBodyLimit() {
        String sse = (":" + "x".repeat(64 * 1024) + "\n").repeat(129);

        assertThatThrownBy(() -> SseResponseParser.extractJsonRpcResponse(
                new BufferedReader(new StringReader(sse)),
                SseResponseParser.expectedReplyId("{\"method\":\"tools/list\",\"id\":7}")))
                .isInstanceOf(IOException.class)
                .hasMessage("SSE response exceeded character limit");
    }

    @Test
    void collectsLargeBatchFromSeparateResponseEvents() throws Exception {
        var request = McpObjectMapper.INSTANCE.createArrayNode();
        var expected = McpObjectMapper.INSTANCE.createArrayNode();
        StringBuilder sse = new StringBuilder();
        for (int id = 1; id <= 64; id++) {
            request.addObject().put("method", "tools/list").put("id", id);
            var response = expected.addObject().put("jsonrpc", "2.0").put("id", id);
            response.putObject("result");
            sse.append("data: ").append(response).append("\n\n");
        }

        String reply = SseResponseParser.extractJsonRpcResponse(
                new BufferedReader(new StringReader(sse.toString())),
                SseResponseParser.expectedReplyId(request.toString()));

        assertThat(McpObjectMapper.INSTANCE.readTree(reply)).isEqualTo(expected);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
    void preservesEveryNullIdInvalidRequestErrorInBatch(boolean separateEvents) throws Exception {
        String first = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"first\"}}";
        String second = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"second\"}}";
        String valid = "{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}";
        String sse = separateEvents
                ? "data: " + first + "\n\ndata: " + valid + "\n\ndata: " + second + "\n\n"
                : "data: [" + first + "," + valid + "," + second + "]\n\n";

        String reply = SseResponseParser.extractJsonRpcResponse(
                new BufferedReader(new StringReader(sse)),
                SseResponseParser.expectedReplyId("[true,{\"method\":\"tools/list\",\"id\":7},false]"));

        assertThat(McpObjectMapper.INSTANCE.readTree(reply))
                .isEqualTo(McpObjectMapper.INSTANCE.readTree("[" + first + "," + valid + "," + second + "]"));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"[]", "[true]"})
    void preservesNullIdInvalidRequestErrorsForInvalidBatches(String request) throws Exception {
        String error = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Invalid Request\"}}";
        String reply = SseResponseParser.extractJsonRpcResponse(
                new BufferedReader(new StringReader("event: message\ndata: " + error + "\n\n")),
                SseResponseParser.expectedReplyId(request));
        assertThat(reply).isNotNull();
        var result = McpObjectMapper.INSTANCE.readTree(reply);
        if (result.isArray()) result = result.get(0);
        assertThat(result.path("id").isNull()).isTrue();
        assertThat(result.path("error").path("code").asInt()).isEqualTo(-32600);
    }

    @Test
    void correlatedSingleReplyPreservesItsOriginalJsonFormatting() throws Exception {
        String response = "{ \"jsonrpc\": \"2.0\", \"id\": 42, \"result\": { \"tools\": [] } }";
        String reply = SseResponseParser.extractJsonRpcResponse(
                new BufferedReader(new StringReader("data: " + response + "\n\n")),
                SseResponseParser.expectedReplyId("{\"id\":42,\"method\":\"tools/list\"}"));
        assertThat(reply).isEqualTo(response);
    }

    @Test
    void extractsJsonRpcResponseFromSingleMessageEvent() {
        String sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}\n\n";
        String result = SseResponseParser.extractJsonRpcResponse(sse);
        assertThat(result).isEqualTo("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}");
    }

    @Test
    void extractsResponseIgnoringNotificationEvents() {
        String sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n"
                + "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}\n\n";
        String result = SseResponseParser.extractJsonRpcResponse(sse);
        assertThat(result).isEqualTo("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}");
    }

    @Test
    void returnsLastDataLineWhenNoIdFieldPresent() {
        String sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"
                + "event: message\ndata: {\"jsonrpc\":\"2.0\",\"error\":{\"code\":-1,\"message\":\"fail\"}}\n\n";
        String result = SseResponseParser.extractJsonRpcResponse(sse);
        assertThat(result).isEqualTo("{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-1,\"message\":\"fail\"}}");
    }

    @Test
    void handlesMultipleDataLinesPerEvent() {
        String sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\"result\":{}}\n\n";
        String result = SseResponseParser.extractJsonRpcResponse(sse);
        assertThat(result).isEqualTo("{\"jsonrpc\":\"2.0\",\n\"id\":1,\"result\":{}}");
    }

    @Test
    void returnsNullForEmptyInput() {
        assertThat(SseResponseParser.extractJsonRpcResponse("")).isNull();
        assertThat(SseResponseParser.extractJsonRpcResponse((String) null)).isNull();
    }

    @Test
    void returnsNullForInputWithNoMessageEvents() {
        String sse = "event: endpoint\ndata: /message\n\n";
        String result = SseResponseParser.extractJsonRpcResponse(sse);
        assertThat(result).isNull();
    }

    @Test
    void treatsDataWithoutEventLineAsDefaultMessageEvent() {
        String sse = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        String result = SseResponseParser.extractJsonRpcResponse(sse);
        assertThat(result).isEqualTo("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
    }

    @Test
    void resetsToDefaultEventTypeAfterBoundary() {
        String sse = "event: endpoint\ndata: /message\n\n"
                + "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        String result = SseResponseParser.extractJsonRpcResponse(sse);
        assertThat(result).isEqualTo("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
    }

    @Test
    void ignoresNonMessageEventTypes() {
        String sse = "event: endpoint\ndata: /message\n\n"
                + "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        String result = SseResponseParser.extractJsonRpcResponse(sse);
        assertThat(result).isEqualTo("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
    }

    @Test
    void doesNotTreatNestedIdAsResponse() {
        String sse = "event: message\n"
                + "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"taskId\":\"abc\"}}\n\n"
                + "event: message\n"
                + "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}\n\n";
        String result = SseResponseParser.extractJsonRpcResponse(sse);
        assertThat(result).isEqualTo("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}");
    }

    @Test
    void nestedIdWithoutTopLevelIdFallsBackToLastData() {
        String sse = "event: message\n"
                + "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"id\":\"nested\"}}\n\n";
        String result = SseResponseParser.extractJsonRpcResponse(sse);
        assertThat(result).isEqualTo(
                "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"id\":\"nested\"}}");
    }

    @Test
    void extractsResponseFromStream() throws IOException {
        String sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        BufferedReader reader = new BufferedReader(new StringReader(sse));

        String result = SseResponseParser.extractJsonRpcResponse(reader);

        assertThat(result).isEqualTo("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
    }

    @Test
    void extractsResponseSkippingNotifications() throws IOException {
        String sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n"
                + "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}\n\n";
        BufferedReader reader = new BufferedReader(new StringReader(sse));

        String result = SseResponseParser.extractJsonRpcResponse(reader);

        assertThat(result).isEqualTo("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[]}}");
    }

    @Test
    void returnsNullFromEmptyStream() throws IOException {
        BufferedReader reader = new BufferedReader(new StringReader(""));

        String result = SseResponseParser.extractJsonRpcResponse(reader);

        assertThat(result).isNull();
    }

    @Test
    void handlesMultipleDataLinesInStream() throws IOException {
        String sse = "event: message\ndata: {\"jsonrpc\":\"2.0\",\ndata: \"id\":1,\"result\":{}}\n\n";
        BufferedReader reader = new BufferedReader(new StringReader(sse));

        String result = SseResponseParser.extractJsonRpcResponse(reader);

        assertThat(result).isEqualTo("{\"jsonrpc\":\"2.0\",\n\"id\":1,\"result\":{}}");
    }

    @Test
    void ignoresNonMessageEventsInStream() throws IOException {
        String sse = "event: endpoint\ndata: /message\n\n"
                + "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        BufferedReader reader = new BufferedReader(new StringReader(sse));

        String result = SseResponseParser.extractJsonRpcResponse(reader);

        assertThat(result).isEqualTo("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
    }

    @Test
    void returnsNullWhenStreamHasNoMessageEvents() throws IOException {
        String sse = "event: endpoint\ndata: /message\n\n";
        BufferedReader reader = new BufferedReader(new StringReader(sse));

        String result = SseResponseParser.extractJsonRpcResponse(reader);

        assertThat(result).isNull();
    }

    @Test
    void extractsEndpointUrlFromStream() throws IOException {
        String sse = "event: endpoint\ndata: /message?sessionId=abc\n\n";
        String result = endpointOf(sse);

        assertThat(result).isEqualTo("/message?sessionId=abc");
    }

    @Test
    void extractEndpointUrlReturnsNullWhenNoEndpointEvent() throws IOException {
        String sse = "event: message\ndata: {\"id\":1}\n\n";
        String result = endpointOf(sse);

        assertThat(result).isNull();
    }

    @Test
    void extractEndpointUrlReturnsNullOnEmptyStream() throws IOException {
        String result = endpointOf("");

        assertThat(result).isNull();
    }

    @Test
    void extractEndpointUrlThrowsWhenSingleLineExceedsCap() {
        StringBuilder huge = new StringBuilder("event: endpoint\ndata: /messages?session=");
        huge.append("a".repeat(2 * 1024 * 1024));
        huge.append("\n\n");
        assertThatThrownBy(() -> endpointOf(huge.toString()))
                .isInstanceOf(IOException.class);
    }

    @Test
    void extractJsonRpcResponseReturnsAsSoonAsFirstIdBearingEventCompletes() throws Exception {
        String completedEvent = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        PipedOutputStream upstream = new PipedOutputStream();
        PipedInputStream stream = new PipedInputStream(upstream, 64 * 1024);
        upstream.write(completedEvent.getBytes(StandardCharsets.UTF_8));
        upstream.flush();
        BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8));

        CompletableFuture<String> reading = CompletableFuture
                .supplyAsync(() -> {
                    try {
                        return SseResponseParser.extractJsonRpcResponse(reader);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
        String result = valueWithin(Duration.ofSeconds(5), reading);

        assertThat(result).isEqualTo("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}");
        upstream.close();
    }

    @Test
    void extractJsonRpcResponseThrowsWhenEventDataExceedsCap() {
        StringBuilder huge = new StringBuilder("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"big\":\"");
        huge.append("a".repeat(2 * 1024 * 1024));
        huge.append("\"}\n\n");
        BufferedReader reader = new BufferedReader(new StringReader(huge.toString()));

        assertThatThrownBy(() -> SseResponseParser.extractJsonRpcResponse(reader))
                .isInstanceOf(IOException.class);
    }

    @Test
    void readsFieldsWithoutTheOptionalSpaceAfterTheColon() throws Exception {
        String response = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}";
        String sse = "event:message\ndata:" + response + "\n\n";

        assertThat(SseResponseParser.extractJsonRpcResponse(sse)).isEqualTo(response);
        assertThat(SseResponseParser.nextDataFrame(SseResponseParser.eventFrames(
                new java.io.ByteArrayInputStream(sse.getBytes(java.nio.charset.StandardCharsets.UTF_8)))).text())
                .isEqualTo("event:message\ndata:" + response + "\n\n");
        assertThat(endpointOf("event:endpoint\ndata:/message?sessionId=1\n\n")).isEqualTo("/message?sessionId=1");
    }

    @Test
    void nextDataFrameSkipsFramesWithoutDataAndKeepsTheRawBytesOfTheOneWithData() throws Exception {
        String sse = ": ping\r\n\r\nid: 2\r\ndata: {\"a\":\r\ndata: 1}\r\n\r\n";
        SseFrameReader frames = SseResponseParser.eventFrames(
                new java.io.ByteArrayInputStream(sse.getBytes(java.nio.charset.StandardCharsets.UTF_8)));

        assertThat(new String(SseResponseParser.nextDataFrame(frames).bytes(), java.nio.charset.StandardCharsets.UTF_8))
                .isEqualTo("id: 2\r\ndata: {\"a\":\r\ndata: 1}\r\n\r\n");
        assertThat(SseResponseParser.nextDataFrame(frames)).isNull();
    }

    @Test
    void nonMessageEventWithoutSpaceIsNotMistakenForAReply() {
        String sse = "event:endpoint\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";

        assertThat(SseResponseParser.extractJsonRpcResponse(sse)).isNull();
    }

    private static String endpointOf(String sse) throws IOException {
        return SseResponseParser.extractEndpointUrl(SseResponseParser.endpointFrames(
                new java.io.ByteArrayInputStream(sse.getBytes(StandardCharsets.UTF_8))));
    }
}
