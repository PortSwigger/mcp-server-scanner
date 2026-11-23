package com.mcpscanner.checks.catalog.unauthenticatedrequestexecution;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.shared.auth.AuthVariantSuite;
import com.mcpscanner.checks.shared.auth.oracle.BaselineEquivalenceOracle;
import com.mcpscanner.checks.shared.probe.ProbeChannel;
import com.mcpscanner.checks.shared.probe.ProbeExchange;
import com.mcpscanner.checks.shared.probe.SimulatedMcpServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class AnonymousExecutionTierTest {

    private static final Map<String, String> AUTHENTICATED = Map.of("Authorization", SimulatedMcpServer.VALID_TOKEN);

    private final BaselineEquivalenceOracle oracle = BaselineEquivalenceOracle.defaultOracle();
    private final EnforcementEvidence enforcement = new EnforcementEvidence(oracle);
    private final AnonymousExecutionTier tier = new AnonymousExecutionTier(oracle, enforcement, new EnforcementProbe(
            new ProbeChannel(SimulatedMcpServer.open().http(), 10),
            new AuthVariantSuite(() -> new BearerTokenAuthStrategy("valid-token"), "canary")));

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    private static AuditSubject subject(SimulatedMcpServer server, String body) {
        HttpRequestResponse baseline = server.exchange(SimulatedMcpServer.request(body, AUTHENTICATED));
        return new AuditSubject(baseline, SeedMessage.of(baseline.request()).orElseThrow(), true);
    }

    private static ProbeExchange anonymous(SimulatedMcpServer server, String body) {
        return ProbeExchange.of(server.exchange(SimulatedMcpServer.request(body, Map.of())));
    }

    private static ProbeExchange anonymousAttempts(SimulatedMcpServer server, String body) {
        return ProbeExchange.of(server.exchange(SimulatedMcpServer.request(body, Map.of())),
                server.exchange(SimulatedMcpServer.request(body, Map.of())));
    }

    private AnonymousExecutionTier tierProbing(SimulatedMcpServer server) {
        return new AnonymousExecutionTier(oracle, enforcement, new EnforcementProbe(
                new ProbeChannel(server.http(), 10), new AuthVariantSuite(
                        () -> new BearerTokenAuthStrategy("valid-token"), "canary")));
    }

    private Optional<Finding> judgeOperation(SimulatedMcpServer server) {
        return tierProbing(server).judge(subject(server, SimulatedMcpServer.toolCall()),
                anonymous(server, SimulatedMcpServer.toolCall()));
    }

    @Test
    void equivalentAnonymousOperationOnAServerWithNoSignOfAuthenticationIsAnAnonymousExecutionFinding() {
        SimulatedMcpServer server = SimulatedMcpServer.open();

        assertThat(judgeOperation(server)).hasValueSatisfying(finding -> {
            assertThat(finding.kind()).isEqualTo(FindingKind.ANONYMOUS_EXECUTION);
            assertThat(finding.variantName()).isEqualTo("credential.none");
            assertThat(finding.evidence()).hasSize(2);
        });
    }

    @Test
    void aServerThatChallengesAnAnonymousPingEnforcesAuthentication() {
        SimulatedMcpServer server = SimulatedMcpServer.open().challengingAnonymousPing();

        assertThat(judgeOperation(server)).hasValueSatisfying(finding -> {
            assertThat(finding.kind()).isEqualTo(FindingKind.ANONYMOUS_EXECUTION_DESPITE_ENFORCEMENT);
            assertThat(finding.evidence()).hasSize(3);
            assertThat(finding.evidence().get(2).response().statusCode()).isEqualTo((short) 401);
        });
    }

    @Test
    void aServerAdvertisingProtectedResourceMetadataEnforcesAuthentication() {
        SimulatedMcpServer server = SimulatedMcpServer.open().advertisingProtectedResourceMetadata();

        assertThat(judgeOperation(server)).map(Finding::kind)
                .hasValue(FindingKind.ANONYMOUS_EXECUTION_DESPITE_ENFORCEMENT);
    }

    @Test
    void anotherAnonymousRefusalOnTheHostEnforcesAuthenticationWithoutAnotherProbe() {
        SimulatedMcpServer server = SimulatedMcpServer.open();
        SimulatedMcpServer enforcing = SimulatedMcpServer.enforcing();
        enforcement.recordRefusal(subject(server, SimulatedMcpServer.toolsList()),
                anonymous(enforcing, SimulatedMcpServer.toolCall()));
        int before = server.received().size();

        assertThat(judgeOperation(server)).map(Finding::kind)
                .hasValue(FindingKind.ANONYMOUS_EXECUTION_DESPITE_ENFORCEMENT);
        assertThat(server.received()).hasSize(before + 2);
    }

    @Test
    void theHostIsProbedForEnforcementOnlyOnce() {
        SimulatedMcpServer server = SimulatedMcpServer.open();
        judgeOperation(server);
        int before = server.received().size();

        judgeOperation(server);

        assertThat(server.received()).hasSize(before + 2);
    }

    @Test
    void anOperationFindingAttachesTheBaselineAndOnlyTheFinalAnonymousReply() {
        SimulatedMcpServer server = SimulatedMcpServer.open();
        AuditSubject subject = subject(server, SimulatedMcpServer.toolCall());
        ProbeExchange anonymous = anonymousAttempts(server, SimulatedMcpServer.toolCall());

        Finding finding = tierProbing(server).judge(subject, anonymous).orElseThrow();

        assertThat(finding.kind()).isEqualTo(FindingKind.ANONYMOUS_EXECUTION);
        assertThat(finding.evidence()).containsExactly(subject.baseline(), anonymous.last());
    }

    @Test
    void anEnforcementFindingAttachesTheBaselineTheFinalAnonymousReplyAndTheEnforcementLast() {
        SimulatedMcpServer server = SimulatedMcpServer.open().challengingAnonymousPing();
        AuditSubject subject = subject(server, SimulatedMcpServer.toolCall());
        ProbeExchange anonymous = anonymousAttempts(server, SimulatedMcpServer.toolCall());

        Finding finding = tierProbing(server).judge(subject, anonymous).orElseThrow();

        assertThat(finding.kind()).isEqualTo(FindingKind.ANONYMOUS_EXECUTION_DESPITE_ENFORCEMENT);
        assertThat(finding.evidence()).hasSize(3).startsWith(subject.baseline(), anonymous.last());
        assertThat(finding.evidence().get(2).response().statusCode()).isEqualTo((short) 401);
    }

    @Test
    void aCatalogFindingAttachesTheBaselineAndOnlyTheFinalAnonymousReply() {
        SimulatedMcpServer server = SimulatedMcpServer.open();
        AuditSubject subject = subject(server, SimulatedMcpServer.toolsList());
        ProbeExchange anonymous = anonymousAttempts(server, SimulatedMcpServer.toolsList());

        Finding finding = tier.judge(subject, anonymous).orElseThrow();

        assertThat(finding.kind()).isEqualTo(FindingKind.ANONYMOUS_CATALOG);
        assertThat(finding.evidence()).containsExactly(subject.baseline(), anonymous.last());
    }

    @Test
    void equivalentAnonymousCatalogIsACatalogFinding() {
        SimulatedMcpServer server = SimulatedMcpServer.open();

        assertThat(tier.judge(subject(server, SimulatedMcpServer.toolsList()),
                anonymous(server, SimulatedMcpServer.toolsList())).orElseThrow().kind())
                .isEqualTo(FindingKind.ANONYMOUS_CATALOG);
    }

    @Test
    void protocolMethodsAndNotificationsAreOutOfThisTier() {
        SimulatedMcpServer server = SimulatedMcpServer.open();

        assertThat(tier.judge(subject(server, SimulatedMcpServer.ping()), anonymous(server, SimulatedMcpServer.ping())))
                .isEmpty();
        assertThat(tier.judge(subject(server, SimulatedMcpServer.notification()),
                anonymous(server, SimulatedMcpServer.notification()))).isEmpty();
    }

    @Test
    void refusedOrDifferentAnonymousResultIsNotAFinding() {
        SimulatedMcpServer enforcing = SimulatedMcpServer.enforcing();
        SimulatedMcpServer soft = SimulatedMcpServer.open().answeringAnonymousCallersWith("log in first");

        assertThat(tier.judge(subject(enforcing, SimulatedMcpServer.toolCall()),
                anonymous(enforcing, SimulatedMcpServer.toolCall()))).isEmpty();
        assertThat(tier.judge(subject(soft, SimulatedMcpServer.toolCall()),
                anonymous(soft, SimulatedMcpServer.toolCall()))).isEmpty();
    }
}
