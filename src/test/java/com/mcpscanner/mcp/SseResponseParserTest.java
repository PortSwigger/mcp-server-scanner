package com.mcpscanner.mcp;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SseResponseParserTest {

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
        BufferedReader reader = new BufferedReader(new StringReader(sse));

        String result = SseResponseParser.extractEndpointUrl(reader);

        assertThat(result).isEqualTo("/message?sessionId=abc");
    }

    @Test
    void extractEndpointUrlReturnsNullWhenNoEndpointEvent() throws IOException {
        String sse = "event: message\ndata: {\"id\":1}\n\n";
        BufferedReader reader = new BufferedReader(new StringReader(sse));

        String result = SseResponseParser.extractEndpointUrl(reader);

        assertThat(result).isNull();
    }

    @Test
    void extractEndpointUrlReturnsNullOnEmptyStream() throws IOException {
        BufferedReader reader = new BufferedReader(new StringReader(""));

        String result = SseResponseParser.extractEndpointUrl(reader);

        assertThat(result).isNull();
    }

    @Test
    void resolveMessageUrlOmitsDefaultPort() {
        String resolved = SseResponseParser.resolveMessageUrl("http://example.com/sse", "/message");

        assertThat(resolved).isEqualTo("http://example.com/message");
    }

    @Test
    void resolveMessageUrlPreservesExplicitNonDefaultPort() {
        String resolved = SseResponseParser.resolveMessageUrl("http://example.com:9000/sse", "/message");

        assertThat(resolved).isEqualTo("http://example.com:9000/message");
    }

    @Test
    void resolveMessageUrlHandlesEndpointPathWithQueryString() {
        String resolved = SseResponseParser.resolveMessageUrl(
                "http://localhost:8080/sse", "/message?sessionId=abc");

        assertThat(resolved).isEqualTo("http://localhost:8080/message?sessionId=abc");
    }

    @Test
    void resolveMessageUrlHandlesIpv6Host() {
        String resolved = SseResponseParser.resolveMessageUrl("http://[::1]:8080/sse", "/message");

        assertThat(resolved).isEqualTo("http://[::1]:8080/message");
    }

    @Test
    void resolveMessageUrlResolvesAbsolutePathAgainstSseUrl() {
        String resolved = SseResponseParser.resolveMessageUrl(
                "https://server.example.com/sse", "/messages?session=abc");

        assertThat(resolved).isEqualTo("https://server.example.com/messages?session=abc");
    }

    @Test
    void resolveMessageUrlRejectsCrossOriginAbsoluteEndpoint() {
        String resolved = SseResponseParser.resolveMessageUrl(
                "https://server.example.com/sse", "https://attacker.com/x");

        assertThat(resolved).isNull();
    }

    @Test
    void resolveMessageUrlRejectsAbsoluteEndpointWithDifferentPort() {
        String resolved = SseResponseParser.resolveMessageUrl(
                "https://server.example.com/sse", "https://server.example.com:8443/messages");

        assertThat(resolved).isNull();
    }

    @Test
    void resolveMessageUrlResolvesRelativePathUnderApiSse() {
        String resolved = SseResponseParser.resolveMessageUrl(
                "https://server.example.com/api/sse", "messages");

        assertThat(resolved).isEqualTo("https://server.example.com/api/messages");
    }

    @Test
    void extractEndpointUrlThrowsWhenSingleLineExceedsCap() {
        StringBuilder huge = new StringBuilder("event: endpoint\ndata: /messages?session=");
        huge.append("a".repeat(2 * 1024 * 1024));
        huge.append("\n\n");
        BufferedReader reader = new BufferedReader(new StringReader(huge.toString()));

        assertThatThrownBy(() -> SseResponseParser.extractEndpointUrl(reader))
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

        String result = CompletableFuture
                .supplyAsync(() -> {
                    try {
                        return SseResponseParser.extractJsonRpcResponse(reader);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                })
                .get(5, TimeUnit.SECONDS);

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
}
