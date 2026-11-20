package com.mcpscanner.checks.catalog.unauthenticatedrequestexecution;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.mcpscanner.checks.shared.auth.AuthVariant;
import com.mcpscanner.checks.shared.auth.RequestMutation;
import com.mcpscanner.checks.shared.auth.VariantFamily;
import com.mcpscanner.checks.shared.probe.ProbeExchange;
import com.mcpscanner.checks.shared.probe.SimulatedMcpServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SettledRejectionTest {

    private static final String AUTH_REFUSAL = "{\"error\":\"unauthorized\"}";
    private static final AuthVariant HEADER_VARIANT = variant(VariantFamily.ROUTING_HEADER);
    private static final AuthVariant PATH_VARIANT = variant(VariantFamily.PATH);
    private static final List<ProbeExchange> CONTROLS = List.of(probe(401, AUTH_REFUSAL));
    private static final String SSE = "Content-Type: text/event-stream";
    private static final String CHUNKED_JSON = "Content-Type: application/json\r\nTransfer-Encoding: chunked";

    private final SettledRejection settled = new SettledRejection();

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void anAnswerIdenticalToTheSeedsRefusedControlIsSettled() {
        assertThat(settled.settles(HEADER_VARIANT, probe(401, AUTH_REFUSAL), CONTROLS)).isTrue();
    }

    @Test
    void aRefusalThatDiffersFromTheControlsIsLeftOpenBecauseAToolOrGatewayMayHaveAnswered() {
        assertThat(settled.settles(HEADER_VARIANT, probe(403, "{\"error\":\"tool admin_export is forbidden\"}"),
                CONTROLS)).isFalse();
        assertThat(settled.settles(HEADER_VARIANT, probe(401,
                "{\"jsonrpc\":\"2.0\",\"id\":11,\"error\":{\"code\":-32001,\"message\":\"Unauthorized tool\"}}"),
                CONTROLS)).isFalse();
    }

    @Test
    void aTemporaryBlockThatDiffersFromTheControlsIsLeftOpen() {
        assertThat(settled.settles(HEADER_VARIANT, probe(403, "<html>Request blocked</html>"), CONTROLS)).isFalse();
        assertThat(settled.settles(HEADER_VARIANT, probe(429, AUTH_REFUSAL), CONTROLS)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(ints = {404, 405})
    void aPathVariantAnsweredAsAnAbsentRouteIsSettled(int status) {
        assertThat(settled.settles(PATH_VARIANT, probe(status, "Not Found"), CONTROLS)).isTrue();
    }

    @Test
    void anAbsentRouteIsSettledOnlyForPathVariants() {
        assertThat(settled.settles(HEADER_VARIANT, probe(404, "Not Found"), CONTROLS)).isFalse();
    }

    @Test
    void aPathVariantAnsweredByTheMcpHandlerIsLeftOpen() {
        assertThat(settled.settles(PATH_VARIANT, probe(404,
                "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32001,\"message\":\"Session not found\"}}"),
                CONTROLS)).isFalse();
    }

    @Test
    void anInterruptedExchangeIsLeftOpen() {
        ProbeExchange interrupted = ProbeExchange.interrupted(answered(401, AUTH_REFUSAL));

        assertThat(settled.settles(HEADER_VARIANT, interrupted, CONTROLS)).isFalse();
    }

    @Test
    void aLostConnectionIsLeftOpen() {
        ProbeExchange lost = ProbeExchange.of(HttpRequestResponse.httpRequestResponse(anonymous(), null));

        assertThat(settled.settles(PATH_VARIANT, lost, CONTROLS)).isFalse();
    }

    @Test
    void sseRefusalsThatDifferOnlyInTheirEventIdsAreTheSameAnswer() {
        List<ProbeExchange> controls = List.of(probe(401, SSE, sseRefusal("evt-1")));

        assertThat(settled.settles(HEADER_VARIANT, probe(401, SSE, sseRefusal("evt-2")), controls)).isTrue();
    }

    @Test
    void chunkedRefusalsFramedDifferentlyAreTheSameAnswer() {
        List<ProbeExchange> controls = List.of(probe(401, CHUNKED_JSON, "18\r\n" + AUTH_REFUSAL + "\r\n0\r\n\r\n"));
        String reframed = "5\r\n" + AUTH_REFUSAL.substring(0, 5) + "\r\n13\r\n" + AUTH_REFUSAL.substring(5)
                + "\r\n0\r\n\r\n";

        assertThat(settled.settles(HEADER_VARIANT, probe(401, CHUNKED_JSON, reframed), controls)).isTrue();
    }

    @Test
    void aChunkedPathVariantAnsweredByTheMcpHandlerIsLeftOpen() {
        String split = "3\r\n{\"j\r\n3e\r\nsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32001,\"message\":\"x\"}}\r\n"
                + "0\r\n\r\n";

        assertThat(settled.settles(PATH_VARIANT, probe(404, CHUNKED_JSON, split), CONTROLS)).isFalse();
    }

    private static String sseRefusal(String eventId) {
        return "id: " + eventId + "\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,"
                + "\"error\":{\"code\":-32001,\"message\":\"Unauthorized\"}}\n\n";
    }

    private static ProbeExchange probe(int status, String head, String body) {
        return ProbeExchange.of(HttpRequestResponse.httpRequestResponse(anonymous(), HttpResponse.httpResponse(
                "HTTP/1.1 " + status + " X\r\n" + head + "\r\n\r\n" + body)));
    }

    private static ProbeExchange probe(int status, String body) {
        return ProbeExchange.of(answered(status, body));
    }

    private static HttpRequestResponse answered(int status, String body) {
        return HttpRequestResponse.httpRequestResponse(anonymous(), HttpResponse.httpResponse(
                "HTTP/1.1 " + status + " X\r\nContent-Type: application/json\r\n\r\n" + body));
    }

    private static HttpRequest anonymous() {
        return SimulatedMcpServer.request(SimulatedMcpServer.toolCall(), Map.of());
    }

    private static AuthVariant variant(VariantFamily family) {
        return AuthVariant.uncontrolled(family, family.name(), new RequestMutation("", request -> request));
    }
}
