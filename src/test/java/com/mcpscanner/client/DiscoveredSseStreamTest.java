package com.mcpscanner.client;

import com.mcpscanner.mcp.RawSseFrame;
import com.mcpscanner.mcp.ServerPings;
import com.mcpscanner.core.protocol.McpFlow;
import com.mcpscanner.core.protocol.McpRequests;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class DiscoveredSseStreamTest {
    private static final String REPLY = "{\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{\"tools\":[]}}";
    private static final McpRequests.Request CALL = new McpRequests.Request(
            "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/list\",\"params\":{}}",
            Map.of("MCP-Protocol-Version", "2024-11-05"));
    private static final SseStreamOpening OPENING = SseStreamOpenings.of("http://127.0.0.1/sse", Map.of(),
            Map.of());
    private static final URI MESSAGE_URL = URI.create("http://127.0.0.1/messages");

    @Test
    void failedPingReplyPostDoesNotFailTheCall() {
        String wire = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"p\",\"method\":\"ping\"}\n\n"
                + "event: message\ndata: " + REPLY + "\n\n";
        List<String> posted = new ArrayList<>();
        ThreadPoolExecutor executor = new ThreadPoolExecutor(1, 1, 1, TimeUnit.SECONDS, new ArrayBlockingQueue<>(1));
        try (var stream = new DiscoveredSseStream(URI.create("http://127.0.0.1/messages"),
                new SseReplyReader(new ByteArrayInputStream(wire.getBytes(StandardCharsets.UTF_8)), executor,
                        Duration.ofSeconds(5)),
                json -> { }, new ServerPings(() -> true), OPENING, SseExchangeListener.IGNORING, request -> {
                    posted.add(request.body());
                    if (request.body().contains("\"result\"")) throw new IllegalStateException("MCP request failed");
                    return new SseMessagePost(new McpFlow.HttpResponse(202, Map.of(), "", true), Optional.empty());
                })) {
            stream.nextEvent();
            stream.post("/messages", CALL);

            assertThat(stream.nextEvent()).contains(REPLY);
            assertThat(posted).hasSize(2);
        } finally {
            executor.shutdownNow();
        }
    }

    @Test
    void tellsTheListenerOfEachPostAndEachEventItHandsBackButNotOfAnsweredServerPings() {
        String reply = "event: message\ndata: " + REPLY + "\n\n";
        String wire = "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":\"p\",\"method\":\"ping\"}\n\n" + reply;
        SseMessagePost accepted = new SseMessagePost(new McpFlow.HttpResponse(202, Map.of(), "", true),
                Optional.empty());
        List<String> heard = new ArrayList<>();
        SseExchangeListener listener = new SseExchangeListener() {
            @Override
            public void messagePosted(SseStreamOpening opening, McpRequests.Request request, SseMessagePost posted) {
                heard.add("post " + (opening == OPENING) + " " + request.body() + " " + (posted == accepted));
            }

            @Override
            public void eventReceived(SseStreamOpening opening, RawSseFrame frame) {
                heard.add("event " + (opening == OPENING) + " " + new String(frame.bytes(), StandardCharsets.UTF_8));
            }
        };
        ThreadPoolExecutor executor = new ThreadPoolExecutor(1, 1, 1, TimeUnit.SECONDS, new ArrayBlockingQueue<>(1));
        try (var stream = new DiscoveredSseStream(MESSAGE_URL,
                new SseReplyReader(new ByteArrayInputStream(wire.getBytes(StandardCharsets.UTF_8)), executor,
                        Duration.ofSeconds(5)),
                json -> { }, new ServerPings(() -> true), OPENING, listener, request -> accepted)) {
            stream.nextEvent();
            stream.post("/messages", CALL);
            stream.nextEvent();

            assertThat(heard).containsExactly(
                    "post true " + CALL.body() + " true",
                    "event true " + reply);
        } finally {
            executor.shutdownNow();
        }
    }
}
