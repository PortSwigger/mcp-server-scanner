package com.mcpscanner.proxy;

import com.fasterxml.jackson.databind.JsonNode;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static java.time.Duration.ofMillis;
import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SseMalformedRequestWaitTest {

    private static final String SSE_URL = "http://localhost:3001/sse";
    private static final long HANDSHAKE_ID = 100L;
    private static final Duration FULL_WAIT = ofSeconds(3);
    private static final Duration SHORT_WAIT = ofMillis(100);
    private static final Duration WELL_UNDER_FULL_WAIT = ofSeconds(2);
    private static final int CONCURRENT_PAIRS = 12;
    private static final String PRELUDE = "event: endpoint\ndata: /message?sessionId=s\n\n"
            + "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":" + HANDSHAKE_ID
            + ",\"result\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},"
            + "\"serverInfo\":{\"name\":\"t\",\"version\":\"0\"}}}\n\n";

    private final SseScanSessionTest.QueueInputStream stream = new SseScanSessionTest.QueueInputStream();
    private final ExecutorService scanners = Executors.newCachedThreadPool();
    private final McpEventLog eventLog = new McpEventLog(null);

    @AfterEach
    void stop() {
        scanners.shutdownNow();
        stream.close();
    }

    @Test
    void serverEchoingIdsAnswersEveryMalformedProbeUnderConcurrentLoad() throws Exception {
        try (SseScanSession session = session(new FixtureServer(true))) {
            List<Future<ProxyResponse>> wellFormed = new ArrayList<>();
            List<Future<ProxyResponse>> malformed = new ArrayList<>();
            for (int i = 1; i <= CONCURRENT_PAIRS; i++) {
                wellFormed.add(forward(session, wellFormedCall(i)));
                malformed.add(forward(session, fuzzedEnvelopeCall(1000 + i)));
            }

            for (int i = 0; i < CONCURRENT_PAIRS; i++) {
                assertAnsweredWithItsOwnId(within(wellFormed.get(i), WELL_UNDER_FULL_WAIT), i + 1);
                assertAnsweredWithItsOwnId(within(malformed.get(i), WELL_UNDER_FULL_WAIT), 1000 + i + 1);
            }
        }
    }

    @Test
    void serverAnsweringWithoutIdsCostsOneFullWaitThenOnlyShortWaitsUnderConcurrentLoad() throws Exception {
        try (SseScanSession session = session(new FixtureServer(false))) {
            ProxyResponse firstProbe = within(forward(session, fuzzedEnvelopeCall(999)), FULL_WAIT.multipliedBy(2));
            assertThat(firstProbe.statusCode()).isEqualTo(502);

            List<Future<ProxyResponse>> wellFormed = new ArrayList<>();
            List<Future<ProxyResponse>> malformed = new ArrayList<>();
            for (int i = 1; i <= CONCURRENT_PAIRS; i++) {
                wellFormed.add(forward(session, wellFormedCall(i)));
                malformed.add(forward(session, fuzzedEnvelopeCall(1000 + i)));
            }

            for (int i = 0; i < CONCURRENT_PAIRS; i++) {
                assertAnsweredWithItsOwnId(within(wellFormed.get(i), WELL_UNDER_FULL_WAIT), i + 1);
                ProxyResponse probe = within(malformed.get(i), WELL_UNDER_FULL_WAIT);
                assertThat(probe.statusCode()).isEqualTo(502);
                assertThat(probe.body()).contains("Timed out");
            }
        }
        assertThat(eventLog.snapshot()).filteredOn(entry -> entry.level() == McpEventLog.Level.INFO)
                .filteredOn(entry -> entry.message().contains("malformed JSON-RPC request")).hasSize(1);
    }

    @Test
    void anIdBearingReplyToAMalformedProbeRestoresTheFullWait() {
        MalformedRequestWaits waits = new MalformedRequestWaits(SHORT_WAIT);

        waits.unanswered(eventLog);
        Duration afterUnanswered = waits.timeout(FULL_WAIT);
        waits.answered();

        assertThat(afterUnanswered).isEqualTo(SHORT_WAIT);
        assertThat(waits.timeout(FULL_WAIT)).isEqualTo(FULL_WAIT);
    }

    private SseScanSession session(FixtureServer server) throws Exception {
        stream.push(PRELUDE);
        return TestSseSessions.builder(SSE_URL, server.client()).requestIds(() -> HANDSHAKE_ID)
                .timeouts(FULL_WAIT, ofSeconds(5)).eventLog(eventLog)
                .malformedRequestWaits(new MalformedRequestWaits(SHORT_WAIT)).build();
    }

    private Future<ProxyResponse> forward(SseScanSession session, String body) {
        return scanners.submit(() -> session.forwardRequest(body, Map.of()));
    }

    private static ProxyResponse within(Future<ProxyResponse> answer, Duration limit) throws Exception {
        return answer.get(limit.toMillis(), TimeUnit.MILLISECONDS);
    }

    private static void assertAnsweredWithItsOwnId(ProxyResponse answer, long id) {
        assertThat(answer.statusCode()).isEqualTo(200);
        assertThat(answer.body()).contains("\"id\":" + id + ",");
    }

    private static String wellFormedCall(long id) {
        return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"method\":\"tools/call\",\"params\":{}}";
    }

    private static String fuzzedEnvelopeCall(long id) {
        return "{\"jsonrpc\":\"2.0$(printf mcp%s $((1+2)))\",\"id\":" + id + ",\"method\":\"tools/list\"}";
    }

    private final class FixtureServer {
        private final boolean echoesIdsOfMalformedRequests;

        FixtureServer(boolean echoesIdsOfMalformedRequests) {
            this.echoesIdsOfMalformedRequests = echoesIdsOfMalformedRequests;
        }

        @SuppressWarnings("unchecked")
        HttpClient client() throws Exception {
            HttpClient http = mock(HttpClient.class);
            HttpResponse<InputStream> sse = mock(HttpResponse.class);
            lenient().when(sse.statusCode()).thenReturn(200);
            when(sse.body()).thenReturn(stream);
            HttpResponse<String> accepted = mock(HttpResponse.class);
            lenient().when(accepted.statusCode()).thenReturn(202);
            lenient().when(accepted.body()).thenReturn("");
            when(http.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenAnswer(call -> {
                HttpRequest request = call.getArgument(0);
                if (!"GET".equals(request.method())) {
                    replyOnStream(McpObjectMapper.INSTANCE.readTree(SseProxyServerTest.extractBody(request)));
                    return accepted;
                }
                return sse;
            });
            return http;
        }

        private void replyOnStream(JsonNode message) {
            if (!message.has("id") || message.path("id").asLong() == HANDSHAKE_ID) {
                return;
            }
            String event = "2.0".equals(message.path("jsonrpc").asText())
                    ? "{\"jsonrpc\":\"2.0\",\"id\":" + message.get("id") + ",\"result\":{}}"
                    : invalidRequestReply(message);
            stream.push("event: message\ndata: " + event + "\n\n");
        }

        private String invalidRequestReply(JsonNode message) {
            String id = echoesIdsOfMalformedRequests ? message.get("id").toString() : "null";
            return "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":-32600,\"message\":\"Invalid\"}}";
        }
    }
}
