package com.mcpscanner.checks.catalog.unauthenticatedrequestexecution;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.shared.auth.AuthVariantSuite;
import com.mcpscanner.checks.shared.auth.oracle.BaselineEquivalenceOracle;
import com.mcpscanner.checks.shared.probe.ControlRefusal;
import com.mcpscanner.checks.shared.probe.IndependentSessionSender;
import com.mcpscanner.checks.shared.probe.ProbeChannel;
import com.mcpscanner.checks.shared.probe.ProbeExchange;
import com.mcpscanner.checks.shared.probe.SimulatedMcpServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class InvalidCredentialTierTest {

    private static final Map<String, String> AUTHENTICATED = Map.of("Authorization", SimulatedMcpServer.VALID_TOKEN);
    private static final Map<String, String> MALFORMED = Map.of("Authorization", "Bearer not_a_real_token_12345");

    private final BaselineEquivalenceOracle oracle = BaselineEquivalenceOracle.defaultOracle();
    private ProbeExchange anonymous;
    private ProbeExchange malformed;
    private int sentBeforeJudging;

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    private Optional<Finding> judge(SimulatedMcpServer server, String body, boolean credentialsConfigured) {
        AuthVariantSuite suite = new AuthVariantSuite(() -> new BearerTokenAuthStrategy("valid-token"), "canary");
        ProbeChannel channel = new ProbeChannel(server.http(), 50);
        IndependentSessionSender sender = new IndependentSessionSender(channel, oracle);
        HttpRequestResponse baseline = server.exchange(SimulatedMcpServer.request(body, AUTHENTICATED));
        AuditSubject subject = new AuditSubject(baseline, SeedMessage.of(baseline.request()).orElseThrow(),
                credentialsConfigured);
        anonymous = twice(server, body, Map.of());
        malformed = twice(server, body, MALFORMED);
        AnonymousRecheck recheck = new AnonymousRecheck(suite, sender, new ControlRefusal(channel, oracle));
        sentBeforeJudging = server.received().size();
        return new InvalidCredentialTier(suite, sender, recheck, oracle).judge(subject, anonymous, malformed);
    }

    private static ProbeExchange twice(SimulatedMcpServer server, String body, Map<String, String> headers) {
        return ProbeExchange.of(server.exchange(SimulatedMcpServer.request(body, headers)),
                server.exchange(SimulatedMcpServer.request(body, headers)));
    }

    @Test
    void attachesTheBaselineTheFinalAnonymousRefusalAndTheFinalMalformedReplyOnly() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().acceptingAnyCredential();

        Finding finding = judge(server, SimulatedMcpServer.toolCall(), true).orElseThrow();

        assertThat(finding.evidence()).hasSize(3).endsWith(anonymous.last(), malformed.last());
        assertThat(finding.evidence().get(0).request().headerValue("Authorization"))
                .isEqualTo(SimulatedMcpServer.VALID_TOKEN);
    }

    @Test
    void theSecondFabricatedCredentialAndTheAnonymousRecheckAreStillSent() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().acceptingAnyCredential();

        assertThat(judge(server, SimulatedMcpServer.toolCall(), true)).isPresent();

        assertThat(server.received()).anyMatch(request ->
                "Bearer invalid_canary".equals(request.headerValue("Authorization")));
        assertThat(server.received().get(server.received().size() - 1).headerValue("Authorization")).isNull();
    }

    @Test
    void reportsBothFabricatedCredentials() {
        Optional<Finding> finding = judge(SimulatedMcpServer.enforcing().acceptingAnyCredential(),
                SimulatedMcpServer.toolCall(), true);

        assertThat(finding).hasValueSatisfying(hit -> {
            assertThat(hit.kind()).isEqualTo(FindingKind.INVALID_CREDENTIAL_ACCEPTED);
            assertThat(hit.variantName()).isEqualTo("credential.garbage-bearer, credential.fabricated-bearer");
            assertThat(hit.variantValue()).isEqualTo("Bearer not_a_real_token_12345, Bearer invalid_canary");
            assertThat(hit.evidence().get(0).request().headerValue("Authorization"))
                    .isEqualTo(SimulatedMcpServer.VALID_TOKEN);
        });
    }

    @Test
    void aServerThatNowAnswersAnonymousCallersIsNotReportedHere() {
        assertThat(judge(SimulatedMcpServer.open(), SimulatedMcpServer.toolCall(), true)).isEmpty();
    }

    @Test
    void scansWithoutConfiguredCredentialsAreNotJudged() {
        assertThat(judge(SimulatedMcpServer.enforcing().acceptingAnyCredential(), SimulatedMcpServer.toolCall(), false))
                .isEmpty();
    }

    @Test
    void protocolMethodsAreNotJudged() {
        assertThat(judge(SimulatedMcpServer.enforcing().acceptingAnyCredential(), SimulatedMcpServer.ping(), true))
                .isEmpty();
    }

    @Test
    void anOperationWhoseResultIsAnEmbeddedErrorIsNotReported() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().acceptingAnyCredential()
                .answeringOperationsWith("{\"data\":\"{\\\"error\\\":\\\"No object ID provided\\\"}\"}");

        assertThat(judge(server, SimulatedMcpServer.toolCall(), true)).isEmpty();
        assertThat(server.received()).hasSize(sentBeforeJudging);
    }
}
