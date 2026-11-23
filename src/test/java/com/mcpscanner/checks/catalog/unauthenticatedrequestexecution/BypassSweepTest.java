package com.mcpscanner.checks.catalog.unauthenticatedrequestexecution;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.shared.auth.AuthVariantSuite;
import com.mcpscanner.checks.shared.auth.CredentialStripper;
import com.mcpscanner.checks.shared.auth.oracle.BaselineEquivalenceOracle;
import com.mcpscanner.checks.shared.probe.ControlRefusal;
import com.mcpscanner.checks.shared.probe.IndependentSessionSender;
import com.mcpscanner.checks.shared.probe.ProbeChannel;
import com.mcpscanner.checks.shared.probe.ProbeExchange;
import com.mcpscanner.checks.shared.probe.SimulatedMcpServer;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

class BypassSweepTest {

    private static final Map<String, String> AUTHENTICATED = Map.of("Authorization", SimulatedMcpServer.VALID_TOKEN);
    private static final Map<String, String> MALFORMED = Map.of("Authorization", "Bearer not_a_real_token_12345");

    private final Supplier<AuthStrategy> strategy = () -> new BearerTokenAuthStrategy("valid-token");
    private final BaselineEquivalenceOracle oracle = BaselineEquivalenceOracle.defaultOracle();
    private final SweepMemo memo = UnauthenticatedRequestExecutionCheck.newSweepMemo();
    private int lastSweepRequests;

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    private Optional<Finding> sweep(SimulatedMcpServer server, int budget) {
        return sweep(server, budget, SimulatedMcpServer.toolCall());
    }

    private Optional<Finding> sweep(SimulatedMcpServer server, int budget, String seedBody) {
        HttpRequestResponse baseline = server.exchange(SimulatedMcpServer.request(seedBody, AUTHENTICATED));
        ProbeExchange refused = ProbeExchange.of(server.exchange(SimulatedMcpServer.request(seedBody, Map.of())));
        return sweep(server, budget, baseline, List.of(refused));
    }

    private Optional<Finding> sweep(SimulatedMcpServer server, int budget, HttpRequestResponse baseline,
                                    List<ProbeExchange> refusedControls) {
        ProbeChannel channel = new ProbeChannel(server.http(), budget);
        IndependentSessionSender sender = new IndependentSessionSender(channel, oracle);
        AuthVariantSuite suite = new AuthVariantSuite(strategy, "canary");
        AnonymousRecheck recheck = new AnonymousRecheck(suite, sender, new ControlRefusal(channel, oracle));
        BypassSweep sweep = new BypassSweep(new SweepVariants(suite,
                new RetainedSessionVariant(new CredentialStripper(strategy)), SweepFamilies.forDirectDelivery()), memo, sender, channel, oracle, recheck);
        AuditSubject subject = new AuditSubject(baseline, SeedMessage.of(baseline.request()).orElseThrow(), true);
        int before = server.received().size();
        Optional<Finding> finding = sweep.sweep(subject, refusedControls);
        lastSweepRequests = server.received().size() - before;
        return finding;
    }

    private static ProbeExchange anonymousAttempts(SimulatedMcpServer server) {
        return ProbeExchange.of(server.exchange(SimulatedMcpServer.request(SimulatedMcpServer.toolCall(), Map.of())),
                server.exchange(SimulatedMcpServer.request(SimulatedMcpServer.toolCall(), Map.of())));
    }

    private static ProbeExchange malformedRefusal(SimulatedMcpServer server) {
        return ProbeExchange.of(server.exchange(SimulatedMcpServer.request(SimulatedMcpServer.toolCall(), MALFORMED)));
    }

    @Test
    void aBypassAttachesTheBaselineTheFinalAnonymousRefusalTheRouteControlAndTheFinalCandidateReply() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/MCP");
        HttpRequestResponse baseline = server.exchange(SimulatedMcpServer.request(SimulatedMcpServer.toolCall(),
                AUTHENTICATED));
        ProbeExchange anonymous = anonymousAttempts(server);

        Finding finding = sweep(server, 500, baseline, List.of(anonymous, malformedRefusal(server))).orElseThrow();

        assertThat(finding.kind()).isEqualTo(FindingKind.AUTHENTICATION_BYPASS);
        assertThat(finding.evidence()).hasSize(4).startsWith(baseline, anonymous.last());
        assertThat(finding.evidence().get(2).request().path().toLowerCase()).startsWith("/mcp/__mcp_canary");
        assertThat(finding.evidence().get(3).request().path()).isEqualTo("/MCP");
        assertThat(finding.evidence()).noneMatch(exchange ->
                MALFORMED.get("Authorization").equals(exchange.request().headerValue("Authorization")));
    }

    @Test
    void theAnonymousRecheckIsStillSentAfterTheHit() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/MCP");
        HttpRequestResponse baseline = server.exchange(SimulatedMcpServer.request(SimulatedMcpServer.toolCall(),
                AUTHENTICATED));

        assertThat(sweep(server, 500, baseline, List.of(anonymousAttempts(server)))).isPresent();

        HttpRequest lastSent = server.received().get(server.received().size() - 1);
        assertThat(lastSent.path()).isEqualTo("/mcp");
        assertThat(lastSent.headerValue("Authorization")).isNull();
    }

    @Test
    void aSessionCredentialAttachesTheBaselineTheFinalAnonymousRefusalAndTheFinalCandidateReply() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().requiringSessions().authenticatingBySession();
        String liveSession = server.openAuthenticatedSession();
        HttpRequestResponse baseline = server.exchange(SimulatedMcpServer.request(SimulatedMcpServer.toolCall(),
                Map.of("Authorization", SimulatedMcpServer.VALID_TOKEN, "Mcp-Session-Id", liveSession)));
        ProbeExchange anonymous = anonymousAttempts(server);

        Finding finding = sweep(server, 500, baseline, List.of(anonymous, malformedRefusal(server))).orElseThrow();

        assertThat(finding.kind()).isEqualTo(FindingKind.SESSION_CREDENTIAL);
        assertThat(finding.evidence()).hasSize(3).startsWith(baseline, anonymous.last());
        assertThat(finding.evidence().get(2).request().headerValue("Mcp-Session-Id")).isEqualTo(liveSession);
        assertThat(finding.evidence().get(2).request().headerValue("Authorization")).isNull();
    }

    @Test
    void firstVariantThatReproducesTheBaselineIsReportedWithItsControls() {
        Optional<Finding> finding = sweep(SimulatedMcpServer.enforcing().withUnguardedPath("/MCP"), 500);

        assertThat(finding).hasValueSatisfying(hit -> {
            assertThat(hit.kind()).isEqualTo(FindingKind.AUTHENTICATION_BYPASS);
            assertThat(hit.variantName()).isEqualTo("path.case");
            assertThat(hit.variantValue()).isEqualTo("/MCP");
            assertThat(hit.evidence()).extracting(exchange -> exchange.request().path())
                    .contains("/mcp", "/MCP")
                    .anyMatch(path -> path.toLowerCase().startsWith("/mcp/__mcp_canary"));
            assertThat(hit.evidence()).filteredOn(exchange -> exchange.request().headerValue("Authorization") == null
                            && exchange.request().path().equals("/mcp"))
                    .extracting(exchange -> (int) exchange.response().statusCode()).contains(401);
        });
    }

    @Test
    void aRefusalThatHasClearedByTheTimeOfTheHitIsNotABypass() {
        SimulatedMcpServer server = SimulatedMcpServer.open().refusingTheFirstAnonymousRequests(1);

        assertThat(sweep(server, 500)).isEmpty();
    }

    @Test
    void variantWhoseOwnControlAlsoSucceedsIsNotABypass() {
        assertThat(sweep(SimulatedMcpServer.enforcing().trustingHeader("X-Real-IP").trustingAnyValue(), 500))
                .isEmpty();
    }

    @Test
    void enforcingServerYieldsNothing() {
        assertThat(sweep(SimulatedMcpServer.enforcing(), 500)).isEmpty();
    }

    @Test
    void exhaustedBudgetStopsTheSweep() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/MCP");

        assertThat(sweep(server, 3)).isEmpty();
    }

    @Test
    void aLaterSeedOfTheSameMethodSkipsEveryVariantAlreadyRefused() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing();
        sweep(server, 500);
        int firstSweep = lastSweepRequests;

        assertThat(sweep(server, 500, otherToolCall())).isEmpty();

        assertThat(firstSweep).isGreaterThan(20);
        assertThat(lastSweepRequests).isZero();
    }

    @Test
    void aLaterSeedOfAnotherMethodSweepsInFull() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing();
        sweep(SimulatedMcpServer.enforcing(), 500, SimulatedMcpServer.toolsList());
        int unmemoised = lastSweepRequests;
        memo.clear();
        sweep(server, 500);

        sweep(server, 500, SimulatedMcpServer.toolsList());

        assertThat(lastSweepRequests).isEqualTo(unmemoised).isGreaterThan(20);
    }

    @Test
    void aLaterSeedStillFindsTheBypassAfterSkippingSettledRejections() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/MCP");
        sweep(server, 500);
        int firstSweep = lastSweepRequests;

        Optional<Finding> finding = sweep(server, 500, otherToolCall());

        assertThat(finding).hasValueSatisfying(hit -> assertThat(hit.variantName()).isEqualTo("path.case"));
        assertThat(lastSweepRequests).isLessThan(firstSweep);
    }

    @Test
    void aToolTheBypassCallerMayNotUseDoesNotHideTheBypassFromOtherTools() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/MCP")
                .denyingToolToBypassCallers("admin_reset");
        assertThat(sweep(server, 500, SimulatedMcpServer.toolCallOf("admin_reset"))).isEmpty();

        Optional<Finding> finding = sweep(server, 500, SimulatedMcpServer.toolCall());

        assertThat(finding).hasValueSatisfying(hit -> assertThat(hit.variantName()).isEqualTo("path.case"));
    }

    @Test
    void aToolForbiddenAtTheHttpLevelDoesNotHideTheBypassFromOtherTools() {
        SimulatedMcpServer server = SimulatedMcpServer.enforcing().withUnguardedPath("/MCP")
                .forbiddingToolToBypassCallers("admin_export");
        assertThat(sweep(server, 500, SimulatedMcpServer.toolCallOf("admin_export"))).isEmpty();

        Optional<Finding> finding = sweep(server, 500, SimulatedMcpServer.toolCall());

        assertThat(finding).hasValueSatisfying(hit -> assertThat(hit.variantName()).isEqualTo("path.case"));
    }

    private static String otherToolCall() {
        return "{\"jsonrpc\":\"2.0\",\"id\":21,\"method\":\"tools/call\",\"params\":{\"name\":\"read_secret\","
                + "\"arguments\":{\"page\":2}}}";
    }
}
