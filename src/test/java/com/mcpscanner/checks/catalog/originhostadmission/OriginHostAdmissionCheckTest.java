package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.HostAudits;
import com.mcpscanner.checks.api.HostSettlement;
import com.mcpscanner.checks.api.HostTrial;
import com.mcpscanner.checks.api.ImplementedKind;
import com.mcpscanner.checks.shared.auth.CredentialHeaders;
import com.mcpscanner.checks.shared.session.ProbeSessions;
import com.mcpscanner.checks.shared.stream.ScriptedEventStreams;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.LOOPBACK_URL;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.PUBLIC_URL;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.TOOLS_RESULT;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.admitting;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.captured;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.hostIsCaptured;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.noForeignOrigin;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.ok;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.originMatchesHost;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.status;
import static com.mcpscanner.checks.catalog.originhostadmission.AdmissionServers.toolsList;
import static org.assertj.core.api.Assertions.assertThat;

class OriginHostAdmissionCheckTest {

    private static final String ORIGIN_ISSUE = "MCP Origin header admission";
    private static final String HOST_ISSUE = "MCP Host header admission";
    private static final String PAIR_ISSUE = "MCP Host and Origin header admission";

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
    }

    @Test
    void declaresAHostCheckWithItsCatalogId() {
        OriginHostAdmissionCheck check = check(NoAuthStrategy::new);

        assertThat(check.descriptor().id()).isEqualTo("origin-host-admission");
        assertThat(check.descriptor().kind()).isEqualTo(CheckKind.HOST);
        assertThat(ImplementedKind.of(check)).isEqualTo(CheckKind.HOST);
        assertThat(check.descriptor().cwes()).extracting(cwe -> cwe.id()).containsExactly(346);
        assertThat(check.descriptor().references()).isNotEmpty();
    }

    @Test
    void anOpenServerYieldsAllThreeFindings() {
        AdmissionServers.Server server = new AdmissionServers.Server(request -> ok(TOOLS_RESULT));

        List<AuditIssue> issues = check(NoAuthStrategy::new).audit(captured(toolsList(LOOPBACK_URL)), server.http);

        assertThat(issues).extracting(AuditIssue::name).containsExactly(ORIGIN_ISSUE, HOST_ISSUE, PAIR_ISSUE);
    }

    @Test
    void aServerThatChecksOnlyHostYieldsOnlyTheOriginFinding() {
        AdmissionServers.Server server = new AdmissionServers.Server(admitting(hostIsCaptured()));

        List<AuditIssue> issues = check(NoAuthStrategy::new).audit(captured(toolsList(LOOPBACK_URL)), server.http);

        assertThat(issues).extracting(AuditIssue::name).containsExactly(ORIGIN_ISSUE);
    }

    @Test
    void aServerThatChecksOnlyOriginYieldsOnlyTheHostFinding() {
        AdmissionServers.Server server = new AdmissionServers.Server(admitting(noForeignOrigin()));

        List<AuditIssue> issues = check(NoAuthStrategy::new).audit(captured(toolsList(LOOPBACK_URL)), server.http);

        assertThat(issues).extracting(AuditIssue::name).containsExactly(HOST_ISSUE);
    }

    @Test
    void aServerThatOnlyRequiresOriginToMatchHostYieldsTheReboundPairFinding() {
        AdmissionServers.Server server = new AdmissionServers.Server(admitting(originMatchesHost()));

        List<AuditIssue> issues = check(NoAuthStrategy::new).audit(captured(toolsList(LOOPBACK_URL)), server.http);

        assertThat(issues).extracting(AuditIssue::name).containsExactly(HOST_ISSUE, PAIR_ISSUE);
    }

    @Test
    void aServerThatValidatesBothHeadersIsSilent() {
        AdmissionServers.Server server = new AdmissionServers.Server(
                admitting(hostIsCaptured().and(noForeignOrigin())));

        assertThat(check(NoAuthStrategy::new).audit(captured(toolsList(LOOPBACK_URL)), server.http)).isEmpty();
        assertThat(server.replays()).hasSize(7);
    }

    @ParameterizedTest
    @ValueSource(ints = {500, 502, 503})
    void serverErrorsOnEveryProbeAreSilent(int serverError) {
        HttpRequest seed = toolsList(LOOPBACK_URL);
        AdmissionServers.Server server = new AdmissionServers.Server(request -> isBaselineShaped(request)
                ? ok(TOOLS_RESULT) : status(serverError, "error"));

        assertThat(check(NoAuthStrategy::new).audit(captured(seed), server.http)).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(ints = {500, 503})
    void aServerErrorBaselineIsSilentAndLeavesTheHostForALaterRequest(int serverError) {
        HostAudits check = audits();
        AdmissionServers.Server failing = new AdmissionServers.Server(request -> status(serverError, "error"));
        AdmissionServers.Server open = new AdmissionServers.Server(request -> ok(TOOLS_RESULT));

        assertThat(check.audit(captured(toolsList(LOOPBACK_URL)), failing.http)).isEmpty();
        assertThat(failing.replays()).hasSize(1);
        assertThat(check.audit(captured(toolsList(LOOPBACK_URL)), open.http)).hasSize(3);
    }

    @Test
    void aDivergingControlIsSilentAndLeavesTheHostForALaterRequest() {
        HostAudits check = audits();
        AdmissionServers.Server flaky = AdmissionServers.Server.sequenced(List.of(
                ok(TOOLS_RESULT), ok(TOOLS_RESULT), ok(TOOLS_RESULT), ok(TOOLS_RESULT), ok(TOOLS_RESULT),
                ok(TOOLS_RESULT), status(500, "")));
        AdmissionServers.Server open = new AdmissionServers.Server(request -> ok(TOOLS_RESULT));

        assertThat(check.audit(captured(toolsList(LOOPBACK_URL)), flaky.http)).isEmpty();
        assertThat(check.audit(captured(toolsList(LOOPBACK_URL)), open.http)).hasSize(3);
    }

    @Test
    void neverReplaysAToolCall() {
        AdmissionServers.Server server = new AdmissionServers.Server(request -> ok(TOOLS_RESULT));
        HttpRequest toolCall = AdmissionServers.seed(LOOPBACK_URL,
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"delete_note\"}}");

        assertThat(check(NoAuthStrategy::new).audit(captured(toolCall), server.http)).isEmpty();
        assertThat(server.received).isEmpty();
    }

    @Test
    void aSkippedToolCallDoesNotClaimTheHost() {
        HostAudits check = audits();
        AdmissionServers.Server server = new AdmissionServers.Server(request -> ok(TOOLS_RESULT));
        check.audit(captured(AdmissionServers.seed(LOOPBACK_URL,
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"x\"}}")), server.http);

        assertThat(check.audit(captured(toolsList(LOOPBACK_URL)), server.http)).hasSize(3);
    }

    @Test
    void probesEachHostOnlyOncePerConnection() {
        HostAudits check = audits();
        AdmissionServers.Server server = new AdmissionServers.Server(request -> ok(TOOLS_RESULT));

        check.audit(captured(toolsList(LOOPBACK_URL)), server.http);
        List<AuditIssue> repeat = check.audit(captured(AdmissionServers.seed(LOOPBACK_URL,
                "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"prompts/list\"}")), server.http);

        assertThat(repeat).isEmpty();
        assertThat(server.replays()).hasSize(7);
    }

    @Test
    void aSilentConclusiveRunStillClaimsTheHost() {
        HostAudits check = audits();
        AdmissionServers.Server safe = new AdmissionServers.Server(admitting(hostIsCaptured().and(noForeignOrigin())));

        check.audit(captured(toolsList(LOOPBACK_URL)), safe.http);
        check.audit(captured(toolsList(LOOPBACK_URL)), safe.http);

        assertThat(safe.replays()).hasSize(7);
    }

    @Test
    void anotherHostIsProbedSeparately() {
        HostAudits check = audits();
        AdmissionServers.Server server = new AdmissionServers.Server(request -> ok(TOOLS_RESULT));

        check.audit(captured(toolsList(LOOPBACK_URL)), server.http);

        assertThat(check.audit(captured(toolsList(PUBLIC_URL)), server.http)).hasSize(3);
    }

    @Test
    void reconnectingProbesTheHostAgain() {
        HostAudits check = audits();
        AdmissionServers.Server server = new AdmissionServers.Server(request -> ok(TOOLS_RESULT));
        check.audit(captured(toolsList(LOOPBACK_URL)), server.http);

        check.clear();

        assertThat(check.audit(captured(toolsList(LOOPBACK_URL)), server.http)).hasSize(3);
    }

    @Test
    void everyRequestAsksForDirectDeliveryAndCarriesTheSessionCredentials() {
        AdmissionServers.Server server = new AdmissionServers.Server(request -> ok(TOOLS_RESULT));

        check(() -> new BearerTokenAuthStrategy("live")).audit(captured(toolsList(LOOPBACK_URL)), server.http);

        assertThat(server.received).allSatisfy(request ->
                assertThat(request.hasHeader(ScannerSentinels.DIRECT_DELIVERY_HEADER)).isTrue());
        assertThat(server.replays()).allSatisfy(request -> {
            assertThat(request.headerValue("Authorization")).isEqualTo("Bearer live");
        });
    }

    @Test
    void anAnonymousLoopbackReboundPairIsMediumAndFirm() {
        AuditIssue pair = issueNamed(PAIR_ISSUE, check(NoAuthStrategy::new), LOOPBACK_URL);

        assertThat(pair.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        assertThat(pair.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
    }

    @Test
    void aCredentialedLoopbackReboundPairIsLow() {
        AuditIssue pair = issueNamed(PAIR_ISSUE, check(() -> new BearerTokenAuthStrategy("live")), LOOPBACK_URL);

        assertThat(pair.severity()).isEqualTo(AuditIssueSeverity.LOW);
    }

    @Test
    void aPublicTargetIsInformational() {
        HostAudits check = audits();
        AdmissionServers.Server server = new AdmissionServers.Server(request -> ok(TOOLS_RESULT));

        assertThat(check.audit(captured(toolsList(PUBLIC_URL)), server.http)).extracting(AuditIssue::severity)
                .containsOnly(AuditIssueSeverity.INFORMATION);
    }

    @Test
    void hostOnlyAdmissionIsTentativeInformation() {
        AuditIssue host = issueNamed(HOST_ISSUE, check(NoAuthStrategy::new), LOOPBACK_URL);

        assertThat(host.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(host.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
    }

    @Test
    void evidenceHoldsTheBaselineTheAdmittedProbesAndTheControl() {
        AuditIssue origin = issueNamed(ORIGIN_ISSUE, check(NoAuthStrategy::new), LOOPBACK_URL);

        assertThat(origin.requestResponses()).hasSize(5);
        assertThat(origin.requestResponses().get(1).request().headerValue("Origin")).isEqualTo("http://evil.example");
        assertThat(origin.requestResponses().get(4).request().hasHeader("Origin")).isFalse();
    }

    @Test
    void aTransientlyFailedProbeLeavesTheHostForALaterRequestButKeepsWhatWasProven() {
        HostAudits check = audits();
        AdmissionServers.Server throttled = new AdmissionServers.Server(request ->
                "attacker.example".equals(request.headerValue("Host")) && request.hasHeader("Origin")
                        ? status(429, "") : ok(TOOLS_RESULT));
        AdmissionServers.Server open = new AdmissionServers.Server(request -> ok(TOOLS_RESULT));

        assertThat(check.audit(captured(toolsList(LOOPBACK_URL)), throttled.http)).extracting(AuditIssue::name)
                .containsExactly(ORIGIN_ISSUE, HOST_ISSUE);
        assertThat(check.audit(captured(toolsList(LOOPBACK_URL)), open.http)).extracting(AuditIssue::name)
                .contains(PAIR_ISSUE);
    }

    @Test
    void aFailingBaselineNeverUsesUpTheHostSoALaterUsableRequestIsProbed() {
        HostAudits check = audits();
        AdmissionServers.Server failing = new AdmissionServers.Server(request -> status(500, ""));
        AdmissionServers.Server open = new AdmissionServers.Server(request -> ok(TOOLS_RESULT));

        for (int attempt = 0; attempt < HostAudits.MAX_INCONCLUSIVE_ATTEMPTS + 2; attempt++) {
            check.audit(captured(toolsList(LOOPBACK_URL)), failing.http);
        }

        assertThat(failing.replays()).hasSize(HostAudits.MAX_INCONCLUSIVE_ATTEMPTS + 2);
        assertThat(check.audit(captured(toolsList(LOOPBACK_URL)), open.http)).hasSize(3);
    }

    @Test
    void stopsRetryingAHostWhoseControlKeepsDiverging() {
        HostAudits check = audits();
        int[] calls = {0};
        AdmissionServers.Server flaky = new AdmissionServers.Server(request ->
                ++calls[0] % 7 == 0 ? status(500, "") : ok(TOOLS_RESULT));

        for (int attempt = 0; attempt < HostAudits.MAX_INCONCLUSIVE_ATTEMPTS + 2; attempt++) {
            check.audit(captured(toolsList(LOOPBACK_URL)), flaky.http);
        }

        assertThat(flaky.replays()).hasSize(7 * HostAudits.MAX_INCONCLUSIVE_ATTEMPTS);
    }

    @Test
    void aProbeThatReturnsAnotherResultIsNotReported() {
        HttpRequest seed = toolsList(LOOPBACK_URL);
        AdmissionServers.Server filtering = new AdmissionServers.Server(request -> isBaselineShaped(request)
                ? ok(TOOLS_RESULT) : ok(AdmissionServers.OTHER_TOOLS_RESULT));

        assertThat(check(NoAuthStrategy::new).audit(captured(seed), filtering.http)).isEmpty();
    }

    @Test
    void aTlsTargetCapsTheReboundPairAtInformation() {
        AuditIssue pair = issueNamed(PAIR_ISSUE, check(NoAuthStrategy::new), "https://127.0.0.1:8443/mcp");

        assertThat(pair.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(pair.detail()).contains("uses TLS");
    }

    @Test
    void originAdmissionIsFirmInformationEvenOnAnAnonymousLoopbackTarget() {
        AuditIssue origin = issueNamed(ORIGIN_ISSUE, check(NoAuthStrategy::new), LOOPBACK_URL);

        assertThat(origin.severity()).isEqualTo(AuditIssueSeverity.INFORMATION);
        assertThat(origin.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
        assertThat(origin.detail()).contains("CORS preflight");
    }

    @Test
    void everyTrialKeepsItsHostClaimedWhenItThrows() {
        assertThat(check(NoAuthStrategy::new).trials()).extracting(HostTrial::settlementOnFailure)
                .containsOnly(HostSettlement.SETTLED);
    }

    @Test
    void theRequestTrialComesFirstThenTheEventStreamAndCorsTrials() {
        assertThat(check(NoAuthStrategy::new).trials()).hasSize(3);
        assertThat(requestSettlementAgainst(new AdmissionServers.Server(request -> ok(TOOLS_RESULT))))
                .isEqualTo(HostSettlement.SETTLED);
    }

    @Test
    void aBaselineThatDoesNotSucceedLeavesTheRequestTrialUnprobed() {
        assertThat(requestSettlementAgainst(new AdmissionServers.Server(request -> status(500, ""))))
                .isEqualTo(HostSettlement.NOT_PROBED);
    }

    @Test
    void aDivergingControlLeavesTheRequestTrialInconclusive() {
        int[] calls = {0};
        AdmissionServers.Server flaky = new AdmissionServers.Server(request ->
                ++calls[0] % 7 == 0 ? status(500, "") : ok(TOOLS_RESULT));

        assertThat(requestSettlementAgainst(flaky)).isEqualTo(HostSettlement.INCONCLUSIVE);
    }

    @Test
    void anUnansweredProbeLeavesTheRequestTrialInconclusive() {
        AdmissionServers.Server throttled = new AdmissionServers.Server(request ->
                request.hasHeader("Origin") ? status(429, "") : ok(TOOLS_RESULT));

        assertThat(requestSettlementAgainst(throttled)).isEqualTo(HostSettlement.INCONCLUSIVE);
    }

    @Test
    void aSilentConclusiveRequestTrialSettles() {
        AdmissionServers.Server safe = new AdmissionServers.Server(admitting(hostIsCaptured().and(noForeignOrigin())));

        assertThat(requestSettlementAgainst(safe)).isEqualTo(HostSettlement.SETTLED);
    }

    @Test
    void theRequestTrialAppliesOnlyToReplaySafeRequests() {
        HostTrial requestTrial = check(NoAuthStrategy::new).trials().get(0);

        assertThat(requestTrial.appliesTo(captured(toolsList(LOOPBACK_URL)))).isTrue();
        assertThat(requestTrial.appliesTo(captured(AdmissionServers.seed(LOOPBACK_URL,
                "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"x\"}}"))))
                .isFalse();
    }

    private static HostSettlement requestSettlementAgainst(AdmissionServers.Server server) {
        return check(NoAuthStrategy::new).trials().get(0).run(captured(toolsList(LOOPBACK_URL)), server.http)
                .settlement();
    }

    private static HostAudits audits() {
        return new HostAudits(check(NoAuthStrategy::new));
    }

    private static boolean isBaselineShaped(HttpRequest request) {
        return !request.hasHeader("Origin") && "127.0.0.1:8765".equals(request.headerValue("Host"));
    }

    private static AuditIssue issueNamed(String name, OriginHostAdmissionCheck check, String url) {
        AdmissionServers.Server server = new AdmissionServers.Server(request -> ok(TOOLS_RESULT));
        return check.audit(captured(toolsList(url)), server.http).stream()
                .filter(issue -> issue.name().equals(name)).findFirst().orElseThrow();
    }

    private static OriginHostAdmissionCheck check(Supplier<AuthStrategy> strategy) {
        return new OriginHostAdmissionCheck(McpEventLog.noop(), new CredentialHeaders(strategy), Optional::empty,
                ScriptedEventStreams.none(), new ProbeSessions(strategy));
    }
}
