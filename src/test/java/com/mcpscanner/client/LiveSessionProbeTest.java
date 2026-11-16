package com.mcpscanner.client;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import com.mcpscanner.core.protocol.McpFlow;

import java.net.ConnectException;
import java.net.http.HttpTimeoutException;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class LiveSessionProbeTest {

    private static LiveSessionProbe probing(Runnable ping) {
        return new LiveSessionProbe(ping, Duration.ofMillis(200));
    }

    private static PingOutcome pingFailing(RuntimeException failure) {
        return probing(() -> { throw failure; }).ping();
    }

    @Test
    void anAnsweredPingMeansTheSessionIsAlive() {
        assertThat(probing(() -> { }).ping()).isEqualTo(PingOutcome.ANSWERED);
    }

    @Test
    void aNotFoundReplyMeansTheSessionWasRefused() {
        assertThat(pingFailing(new McpHttpStatusException("ping", 404))).isEqualTo(PingOutcome.SESSION_REFUSED);
    }

    @Test
    void aServerErrorIsInconclusive() {
        assertThat(pingFailing(new McpHttpStatusException("ping", 500))).isEqualTo(PingOutcome.INCONCLUSIVE);
    }

    @Test
    void aConnectionRefusedMeansUnreachable() {
        assertThat(pingFailing(new IllegalStateException("MCP request failed: refused",
                new ConnectException("refused")))).isEqualTo(PingOutcome.UNREACHABLE);
    }

    @Test
    void noResponseThroughBurpMeansTimedOut() {
        assertThat(pingFailing(new IllegalStateException("MCP request failed: No response",
                new BurpNoResponseException("No response from http://127.0.0.1:8651/mcp through Burp"))))
                .isEqualTo(PingOutcome.TIMED_OUT);
    }

    @Test
    void aTransportTimeoutMeansTimedOut() {
        assertThat(pingFailing(new IllegalStateException("MCP request failed",
                new HttpTimeoutException("request timed out")))).isEqualTo(PingOutcome.TIMED_OUT);
    }

    @Test
    void aReinitialisationRefusedWith404MeansTheSessionWasRefused() {
        assertThat(pingFailing(handshakeRefusedWith(404))).isEqualTo(PingOutcome.SESSION_REFUSED);
    }

    @Test
    void aReinitialisationRefusedWithAnotherStatusIsInconclusive() {
        assertThat(pingFailing(handshakeRefusedWith(500))).isEqualTo(PingOutcome.INCONCLUSIVE);
    }

    @Test
    void anUnrelatedIllegalArgumentIsInconclusive() {
        assertThat(pingFailing(new IllegalArgumentException("Reply id 7 does not match request id 3 failed: HTTP 404")))
                .isEqualTo(PingOutcome.INCONCLUSIVE);
    }

    @Test
    void anUnparseableReplyIsInconclusive() {
        assertThat(pingFailing(new IllegalStateException("not json"))).isEqualTo(PingOutcome.INCONCLUSIVE);
    }

    @Test
    void aPingThatNeverAnswersTimesOutAndInterruptsTheStuckCall() throws InterruptedException {
        CountDownLatch interrupted = new CountDownLatch(1);

        PingOutcome outcome = probing(() -> {
            try {
                Thread.sleep(5_000);
            } catch (InterruptedException e) {
                interrupted.countDown();
            }
        }).ping();

        assertThat(outcome).isEqualTo(PingOutcome.TIMED_OUT);
        assertThat(interrupted.await(2, TimeUnit.SECONDS)).isTrue();
    }

    private static IllegalArgumentException handshakeRefusedWith(int status) {
        McpFlow flow = new McpFlow(1024, 64);
        try {
            flow.openHttp(request -> request.body().contains("notifications/initialized")
                    ? new McpFlow.HttpResponse(status, Map.of(), "", true)
                    : new McpFlow.HttpResponse(200, Map.of(),
                    "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\"}}", true),
                    "client", "1");
        } catch (IllegalArgumentException refused) {
            return refused;
        }
        throw new AssertionError("expected the handshake to be refused");
    }
}
