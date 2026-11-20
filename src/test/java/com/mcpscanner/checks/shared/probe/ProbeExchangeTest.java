package com.mcpscanner.checks.shared.probe;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.checks.shared.session.McpSessionHandshake;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ProbeExchangeTest {

    private static final Map<String, String> JSON = Map.of("Content-Type", "application/json");

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void lastIsTheFinalExchange() {
        HttpRequestResponse first = mock(HttpRequestResponse.class);
        HttpRequestResponse second = mock(HttpRequestResponse.class);

        assertThat(ProbeExchange.of(first, second).last()).isSameAs(second);
        assertThat(ProbeExchange.of(first).exchanges()).containsExactly(first);
    }

    @Test
    void anEmptyExchangeIsRejected() {
        assertThatThrownBy(() -> new ProbeExchange(List.of())).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void aSingleExchangeIsItsOwnAnswer() {
        HttpRequestResponse first = sent(probe());

        assertThat(ProbeExchange.of(first).answer()).isSameAs(first);
    }

    @Test
    void aRefusedFreshSessionHandshakeLeavesTheProbeAsTheAnswer() {
        HttpRequestResponse first = sent(probe());
        HttpRequestResponse initialize = sent(freshSessionInitialize());

        assertThat(ProbeExchange.of(first, initialize).answer()).isSameAs(first);
    }

    @Test
    void theProbeRetriedInTheFreshSessionIsTheAnswer() {
        HttpRequestResponse first = sent(probe());
        HttpRequestResponse initialize = sent(freshSessionInitialize());
        HttpRequestResponse retried = sent(probe());

        assertThat(ProbeExchange.of(first, initialize, retried).answer()).isSameAs(retried);
    }

    @Test
    void aResentRefusedHandshakeStillLeavesTheProbeAsTheAnswer() {
        HttpRequestResponse first = sent(probe());

        ProbeExchange confirmed = ProbeExchange.of(first, sent(freshSessionInitialize()))
                .followedBy(sent(freshSessionInitialize()));

        assertThat(confirmed.answer()).isSameAs(first);
    }

    @Test
    void anInitializeProbeWithItsOwnIdIsTheAnswer() {
        HttpRequestResponse first = sent(SimulatedMcpServer.request(
                "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"initialize\",\"params\":{}}", JSON));
        HttpRequestResponse initialize = sent(freshSessionInitialize());
        HttpRequestResponse retried = sent(first.request());

        assertThat(ProbeExchange.of(first, initialize, retried).answer()).isSameAs(retried);
    }

    @Test
    void whenTheProbeWasRejectedForAMissingSessionTheRefusedHandshakeIsTheAnswer() {
        HttpRequestResponse missingSession = sent(probe(), 400);
        HttpRequestResponse refusedInitialize = sent(freshSessionInitialize(), 401);

        assertThat(ProbeExchange.of(missingSession, refusedInitialize).answer()).isSameAs(refusedInitialize);
    }

    @Test
    void whenTheProbeHitAServerErrorTheRefusedHandshakeIsTheAnswer() {
        HttpRequestResponse serverError = sent(probe(), 500);
        HttpRequestResponse refusedInitialize = sent(freshSessionInitialize(), 401);

        assertThat(ProbeExchange.of(serverError, refusedInitialize).answer()).isSameAs(refusedInitialize);
    }

    @Test
    void whenTheProbeWasRefusedItselfItStaysTheAnswerOverTheRefusedHandshake() {
        HttpRequestResponse refusedProbe = sent(probe(), 401);

        assertThat(ProbeExchange.of(refusedProbe, sent(freshSessionInitialize(), 401)).answer()).isSameAs(refusedProbe);
    }

    private static HttpRequestResponse sent(HttpRequest request, int status) {
        HttpRequestResponse exchange = sent(request);
        HttpResponse response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn((short) status);
        when(exchange.response()).thenReturn(response);
        return exchange;
    }

    private static HttpRequest probe() {
        return SimulatedMcpServer.request(SimulatedMcpServer.toolCall(), JSON);
    }

    private static HttpRequest freshSessionInitialize() {
        return McpSessionHandshake.named(IndependentSessionSender.INITIALIZE_ID).initialize(probe());
    }

    private static HttpRequestResponse sent(HttpRequest request) {
        HttpRequestResponse exchange = mock(HttpRequestResponse.class);
        when(exchange.request()).thenReturn(request);
        return exchange;
    }
}
