package com.mcpscanner.client;

import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.FakeMcpServer;
import com.mcpscanner.testutil.ScriptedProtocolTransport;
import com.mcpscanner.testutil.ScriptedProtocolTransport.ScriptedIoFailure;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class StreamedReplyFallbackTransportTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final URI STREAMING = URI.create("https://streams.example.test/mcp");
    private static final URI JSON = URI.create("https://json.example.test/mcp");

    private final ScriptedProtocolTransport burp = new ScriptedProtocolTransport(request -> {
        if (request.uri().getHost().equals(STREAMING.getHost()) && request.body().contains("tools/call")) {
            throw new ScriptedIoFailure(new BurpStreamingResponseException(request.uri()));
        }
        return FakeMcpServer.respond(request);
    });
    private final AtomicBoolean jdkFails = new AtomicBoolean();
    private final ScriptedProtocolTransport jdk = new ScriptedProtocolTransport(request -> {
        if (jdkFails.get()) {
            throw new ScriptedIoFailure(new IOException("connection refused"));
        }
        return FakeMcpServer.respond(request);
    });
    private final AtomicBoolean forwarding = new AtomicBoolean(true);
    private final McpEventLog eventLog = new McpEventLog(null);
    private final StreamedReplyFallbackTransport transport =
            new StreamedReplyFallbackTransport(burp, jdk, forwarding::get, eventLog);

    @Test
    void sendsThroughBurpWhileBurpPassesTheReply() throws Exception {
        transport.send(toolsCall(JSON), TIMEOUT).close();

        assertThat(burp.requests()).hasSize(1);
        assertThat(jdk.requests()).isEmpty();
    }

    @Test
    void resendsAForwardBurpRefusedAsStreamedThroughTheJdkClient() throws Exception {
        transport.send(toolsCall(STREAMING), TIMEOUT).close();

        assertThat(burp.requests()).hasSize(1);
        assertThat(jdk.requests()).containsExactly(toolsCall(STREAMING));
    }

    @Test
    void sendsLaterForwardsOfTheStreamedMethodStraightThroughTheJdkClient() throws Exception {
        transport.send(toolsCall(STREAMING), TIMEOUT).close();
        transport.send(toolsCall(STREAMING), TIMEOUT).close();
        transport.send(toolsCall(JSON), TIMEOUT).close();

        assertThat(burp.requests()).extracting(ProtocolHttpRequest::uri).containsExactly(STREAMING, JSON);
        assertThat(jdk.requests()).hasSize(2);
    }

    @Test
    void keepsMethodsBurpServesOnBurpAfterAnotherMethodStreamed() throws Exception {
        transport.send(toolsCall(STREAMING), TIMEOUT).close();
        transport.send(toolsList(STREAMING), TIMEOUT).close();

        assertThat(burp.methods()).containsExactly("tools/call", "tools/list");
        assertThat(jdk.methods()).containsExactly("tools/call");
    }

    @Test
    void triesBurpAgainWhenTheJdkResendFails() throws Exception {
        jdkFails.set(true);
        assertThatThrownBy(() -> transport.send(toolsCall(STREAMING), TIMEOUT)).isInstanceOf(IOException.class);
        jdkFails.set(false);

        transport.send(toolsCall(STREAMING), TIMEOUT).close();

        assertThat(burp.requests()).hasSize(2);
    }

    @Test
    void triesBurpAgainAndWarnsAgainOnceTheStreamingRoutesAreForgotten() throws Exception {
        transport.send(toolsCall(STREAMING), TIMEOUT).close();

        transport.forgetStreamingRoutes();
        transport.send(toolsCall(STREAMING), TIMEOUT).close();

        assertThat(burp.requests()).hasSize(2);
        assertThat(messages()).hasSize(2);
    }

    @Test
    void warnsOnceForEachStreamingRouteThatItsForwardsBypassBurp() throws Exception {
        transport.send(toolsCall(STREAMING), TIMEOUT).close();
        transport.send(toolsCall(STREAMING), TIMEOUT).close();

        assertThat(eventLog.snapshot()).singleElement().satisfies(entry -> {
            assertThat(entry.level()).isEqualTo(McpEventLog.Level.WARN);
            assertThat(entry.message()).contains("https://streams.example.test", "tools/call", "text/event-stream",
                    "bypass Burp", "client TLS certificate", "upstream proxy", "twice", "in flight");
        });
    }

    @Test
    void anEmptyReplyIsNotResentWhenNothingShowsTheRouteStreams() {
        ScriptedProtocolTransport emptying = new ScriptedProtocolTransport(request -> {
            throw new ScriptedIoFailure(new ConnectionClosedBeforeReplyException(request.uri()));
        });
        StreamedReplyFallbackTransport unproven =
                new StreamedReplyFallbackTransport(emptying, jdk, forwarding::get, eventLog);

        assertThatThrownBy(() -> unproven.send(toolsCall(STREAMING), TIMEOUT))
                .isInstanceOf(ConnectionClosedBeforeReplyException.class);
        assertThat(jdk.requests()).isEmpty();
    }

    @Test
    void anEmptyReplyToASendInFlightWhenAnotherLearnedTheRouteStreamsIsNeverResentBecauseTheCallMayHaveWritten()
            throws Exception {
        CountDownLatch secondInFlight = new CountDownLatch(1);
        CountDownLatch firstLearnedTheRoute = new CountDownLatch(1);
        ScriptedProtocolTransport racing = new ScriptedProtocolTransport(request -> {
            if (request.body().contains("\"id\":1,")) {
                await(secondInFlight);
                throw new ScriptedIoFailure(new BurpStreamingResponseException(request.uri()));
            }
            secondInFlight.countDown();
            await(firstLearnedTheRoute);
            throw new ScriptedIoFailure(new ConnectionClosedBeforeReplyException(request.uri()));
        });
        StreamedReplyFallbackTransport concurrent =
                new StreamedReplyFallbackTransport(racing, jdk, forwarding::get, eventLog);
        ExecutorService senders = Executors.newFixedThreadPool(2);
        try {
            Future<ProtocolHttpResponse> second = senders.submit(() -> concurrent.send(toolsCall(STREAMING, 2), TIMEOUT));
            Future<ProtocolHttpResponse> first = senders.submit(() -> concurrent.send(toolsCall(STREAMING, 1), TIMEOUT));
            first.get(10, TimeUnit.SECONDS).close();
            firstLearnedTheRoute.countDown();

            assertThatThrownBy(() -> second.get(10, TimeUnit.SECONDS))
                    .hasRootCauseInstanceOf(ConnectionClosedBeforeReplyException.class);
        } finally {
            senders.shutdownNow();
        }

        assertThat(jdk.requests()).containsExactly(toolsCall(STREAMING, 1));
    }

    @Test
    void leavesTheStreamingRefusalToTheCallerOutsideAForward() {
        forwarding.set(false);

        assertThatThrownBy(() -> transport.send(toolsCall(STREAMING), TIMEOUT))
                .isInstanceOf(BurpStreamingResponseException.class);
        assertThat(jdk.requests()).isEmpty();
        assertThat(eventLog.snapshot()).isEmpty();
    }

    private List<String> messages() {
        return eventLog.snapshot().stream().map(McpEventLog.LogEntry::message).toList();
    }

    private static ProtocolHttpRequest toolsCall(URI target) {
        return toolsCall(target, 1);
    }

    private static ProtocolHttpRequest toolsCall(URI target, int id) {
        return post(target, "{\"jsonrpc\":\"2.0\",\"id\":" + id
                + ",\"method\":\"tools/call\",\"params\":{\"name\":\"t\"}}");
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("timed out");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
        }
    }

    private static ProtocolHttpRequest toolsList(URI target) {
        return post(target, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}");
    }

    private static ProtocolHttpRequest post(URI target, String body) {
        return new ProtocolHttpRequest(target, "POST", Map.of("Content-Type", "application/json"), body);
    }
}
