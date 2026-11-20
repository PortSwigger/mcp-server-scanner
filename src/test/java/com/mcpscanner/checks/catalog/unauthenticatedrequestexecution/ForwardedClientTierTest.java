package com.mcpscanner.checks.catalog.unauthenticatedrequestexecution;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.shared.auth.ClientAddressVariants;
import com.mcpscanner.checks.shared.auth.oracle.BaselineEquivalenceOracle;
import com.mcpscanner.checks.shared.probe.AuthenticatedBaseline;
import com.mcpscanner.checks.shared.probe.ProbeChannel;
import com.mcpscanner.checks.shared.probe.SimulatedMcpServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static com.mcpscanner.checks.shared.probe.SimulatedMcpServer.ping;
import static com.mcpscanner.checks.shared.probe.SimulatedMcpServer.request;
import static com.mcpscanner.checks.shared.probe.SimulatedMcpServer.toolCall;
import static com.mcpscanner.checks.shared.probe.SimulatedMcpServer.toolsList;
import static org.assertj.core.api.Assertions.assertThat;

class ForwardedClientTierTest {

    private static final Map<String, String> AUTHENTICATED = Map.of("Authorization", SimulatedMcpServer.VALID_TOKEN);

    private final BaselineEquivalenceOracle oracle = BaselineEquivalenceOracle.defaultOracle();
    private final ScopeClaims claims = new ScopeClaims();
    private final Supplier<AuthStrategy> strategy = () -> new BearerTokenAuthStrategy("valid-token");

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    private Optional<Finding> judge(SimulatedMcpServer server, String body, Map<String, String> headers) {
        HttpRequestResponse baseline = server.exchange(request(body, headers));
        AuditSubject subject = new AuditSubject(baseline, SeedMessage.of(baseline.request()).orElseThrow(), true);
        return new ForwardedClientTier(new ClientAddressVariants(), new AuthenticatedBaseline(strategy),
                new ProbeChannel(server.http(), 500), oracle, claims).judge(subject);
    }

    private Optional<Finding> judge(SimulatedMcpServer server, String body) {
        return judge(server, body, AUTHENTICATED);
    }

    @Test
    void reportsASourceAddressGateThatFollowsXForwardedFor() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().restrictingSourceAddressesTrusting("X-Forwarded-For");

        Finding finding = judge(server, toolCall()).orElseThrow();

        assertThat(finding.kind()).isEqualTo(FindingKind.FORWARDED_CLIENT_ADDRESS_TRUSTED);
        assertThat(finding.variantName()).isEqualTo("forwarded-for");
        assertThat(finding.variantValue()).isEqualTo("127.0.0.1");
        assertThat(finding.evidence()).extracting(exchange -> exchange.request().headerValue("X-Forwarded-For"))
                .containsExactly(null, "203.0.113.7", "127.0.0.1");
        assertThat(server.received()).allMatch(request ->
                SimulatedMcpServer.VALID_TOKEN.equals(request.headerValue("Authorization")));
    }

    @Test
    void theRepeatedExternalAddressRefusalIsStillSentAfterTheAdmittedRequest() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().restrictingSourceAddressesTrusting("X-Forwarded-For");

        assertThat(judge(server, toolCall())).isPresent();

        assertThat(server.received()).extracting(request -> request.headerValue("X-Forwarded-For"))
                .containsExactly(null, "203.0.113.7", "127.0.0.1", "203.0.113.7");
    }

    @Test
    void probesCarryTheConfiguredCredentialsDirectlyRatherThanRelyingOnTheProxyToInjectThem() {
        SimulatedMcpServer server = SimulatedMcpServer.open().restrictingSourceAddressesTrusting("X-Forwarded-For");

        judge(server, toolCall(), Map.of()).orElseThrow();

        assertThat(server.received().subList(1, server.received().size())).allSatisfy(probe -> {
            assertThat(probe.headerValue("Authorization")).isEqualTo(SimulatedMcpServer.VALID_TOKEN);
            assertThat(probe.headerValue("X-Mcp-Scanner-Strip-Auth")).isNotNull();
        });
    }

    @Test
    void movesOnToTheNextHeaderWhenTheGateIgnoresTheFirst() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().restrictingSourceAddressesTrusting("X-Real-IP");

        Finding finding = judge(server, toolsList()).orElseThrow();

        assertThat(finding.variantName()).isEqualTo("client.x-real-ip");
    }

    @Test
    void serverWithoutASourceAddressGateCostsOneRequestPerHeader() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing();

        assertThat(judge(server, toolCall())).isEmpty();
        assertThat(server.received()).hasSize(1 + 4);
    }

    @Test
    void serverThatRefusesAnyForwardingHeaderIsNotReported() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().rejectingForwardedHeaders();

        assertThat(judge(server, toolCall())).isEmpty();
    }

    @Test
    void reproducibleProxyErrorIsNotTakenAsARefusal() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().restrictingSourceAddressesTrusting("X-Forwarded-For")
                .refusingSourcesThroughAFailingProxy();

        assertThat(judge(server, toolCall())).isEmpty();
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "429|{\"error\":\"too many requests\"}",
            "503|{\"error\":\"stream limit reached\"}",
            "502|{\"error\":\"Proxy error: initialize offering protocolVersion 2025-11-25 failed: HTTP 429\"}",
            "502|{\"error\":\"SSE proxy error: SSE stream closed without sending endpoint event\"}"})
    void transientFailuresThatAlternateWithSuccessAreNotReported(int status, String body) {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().failingEverySecondRequest(status, body);

        assertThat(judge(server, toolCall())).isEmpty();
    }

    @Test
    void serverErrorThatDoesNotReproduceIsNotReported() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().restrictingSourceAddressesTrusting("X-Forwarded-For")
                .refusingSourcesThroughAFailingProxyVariably();

        assertThat(judge(server, toolCall())).isEmpty();
    }

    @Test
    void rateLimitedProbeIsNotTakenAsARefusal() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().throttlingForwardedHeaders();

        assertThat(judge(server, toolCall())).isEmpty();
    }

    @Test
    void stopsProbingOnceAForwardedProbeIsRateLimited() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().throttlingForwardedHeaders();

        judge(server, toolCall());

        assertThat(server.received()).filteredOn(request -> request.headerValue("X-Forwarded-For") != null)
                .hasSize(1);
        assertThat(server.received()).filteredOn(request -> request.headerValue("X-Real-IP") != null).isEmpty();
    }

    @Test
    void judgesEachEndpointMethodOncePerConnection() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().restrictingSourceAddressesTrusting("X-Forwarded-For");
        judge(server, toolCall());
        int sentForTheFirstCall = server.received().size();

        assertThat(judge(server, toolCall())).isEmpty();
        assertThat(server.received()).hasSize(sentForTheFirstCall + 1);

        claims.clear();
        assertThat(judge(server, toolCall())).isPresent();
    }

    @Test
    void protocolMethodsAreNotProbed() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().restrictingSourceAddressesTrusting("X-Forwarded-For");

        assertThat(judge(server, ping())).isEmpty();
        assertThat(server.received()).hasSize(1);
    }

    @Test
    void unsuccessfulBaselineIsNotProbed() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().restrictingSourceAddressesTrusting("X-Forwarded-For");

        assertThat(judge(server, toolCall(), Map.of())).isEmpty();
        assertThat(server.received()).hasSize(1);
    }
}
