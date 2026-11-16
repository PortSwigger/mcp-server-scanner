package com.mcpscanner.checks.catalog.sessionbinding;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.CheckCatalog;
import com.mcpscanner.checks.api.CheckKind;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.checks.api.crossidentity.FakeMcpTarget;
import com.mcpscanner.checks.api.crossidentity.FakeServers;
import com.mcpscanner.checks.api.crossidentity.TestPrincipals;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.toolCall;
import static com.mcpscanner.checks.catalog.sessionbinding.SessionBindingHarness.withPeerB;
import static org.assertj.core.api.Assertions.assertThat;

class SessionBindingCheckTest {

    private static final String RESULT_AVAILABLE = "MCP operation result available to another principal";
    private static final String SESSION_REBOUND = "MCP session rebound to another principal's credential";
    private static final HttpRequest SESSION_RECORD = inSession(toolCall("read_session_record", "{}", "A"), "sess-A");

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    private static HttpRequest inSession(HttpRequest seed, String session) {
        return seed.withAddedHeader("Mcp-Session-Id", session);
    }

    private static boolean peerOnLiveSession(HttpRequest request) {
        return "sess-A".equals(request.headerValue("Mcp-Session-Id")) && "B".equals(FakeMcpTarget.principal(request));
    }

    @Test
    void factoryIsDiscoveredUnderTheCatalogIdAsADefaultEnabledRequestCheck() {
        assertThat(CheckCatalog.discover(CheckServices.standalone()).find("session-binding")).get()
                .satisfies(check -> {
                    assertThat(check.descriptor().displayName()).isEqualTo("MCP session binding across identities");
                    assertThat(check.descriptor().kind()).isEqualTo(CheckKind.REQUEST);
                    assertThat(check.descriptor().defaultEnabled()).isTrue();
                });
    }

    @Test
    void sessionBindingProvenByTheOwnerMarkerIsHighAndFirm() {
        var run = withPeerB().ownerMarker("ALICE-SESSION-RECORD").run(FakeServers.sessions(false), SESSION_RECORD);

        assertThat(run.issues()).filteredOn(issue -> issue.detail().contains("Probe: session."))
                .singleElement().satisfies(issue -> {
                    assertThat(issue.name()).isEqualTo(RESULT_AVAILABLE);
                    assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
                    assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
                });
    }

    @Test
    void sessionBindingWithoutTheOwnerMarkerIsMediumAndTentative() {
        var run = withPeerB().run(FakeServers.sessions(false), SESSION_RECORD);

        assertThat(run.issues()).filteredOn(issue -> issue.detail().contains("Probe: session."))
                .singleElement().satisfies(issue -> {
                    assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
                    assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
                });
    }

    @Test
    void findingsAreFiledUnderTheEndpointOfTheBaseRequest() {
        var run = withPeerB().run(FakeServers.sessions(false), SESSION_RECORD);

        assertThat(run.issues()).isNotEmpty().allMatch(issue -> issue.baseUrl().equals(SESSION_RECORD.url()));
    }

    @Test
    void anonymousServedAsThePeerContinuesAndNeverReportsTheSessionIdAsACredential() {
        var run = withPeerB().run(FakeServers.processWideCache(), inSession(toolCall("list_orgs", "{}", "A"), "sess-A"));

        assertThat(run.decisions()).contains("anonymous_served_as_peer");
        assertThat(run.firedFamily("session")).isTrue();
        assertThat(run.issues()).allMatch(issue -> issue.name().equals(RESULT_AVAILABLE));
    }

    @Test
    void anonymousOtherResultWithoutAPeerWitnessStops() {
        var run = withPeerB().run(FakeServers.unauthenticatedSessionEcho(), SESSION_RECORD);

        assertThat(run.issues()).isEmpty();
        assertThat(run.decisions()).contains("anonymous_operation_success");
    }

    @Test
    void callerChosenSessionOnAStatelessServerIsBound() {
        var run = withPeerB().run(FakeServers.statelessCallerSessions(),
                inSession(toolCall("list_orgs", "{}", "A"), "chosen-A"));

        assertThat(run.decisions()).contains("anonymous_served_as_peer");
        assertThat(run.firedFamily("session")).isTrue();
    }

    @Test
    void terminatedSessionIsNotARebind() {
        var run = withPeerB().run(FakeServers.terminatingSessions(false), SESSION_RECORD);

        assertThat(run.firedFamily("session-rebind")).isFalse();
    }

    @Test
    void terminationReturnedAsAToolErrorIsNotARebind() {
        var run = withPeerB().run(FakeServers.terminatingSessions(true), SESSION_RECORD);

        assertThat(run.firedFamily("session-rebind")).isFalse();
        assertThat(run.decisions()).contains("session_rebind:not_peer_reply");
    }

    @Test
    void peerCredentialOnTheOwnersSessionFiresOnlyWhenSessionsAreUnbound() {
        var vulnerable = withPeerB().run(FakeServers.sessions(false), SESSION_RECORD);
        var fixed = withPeerB().run(FakeServers.sessions(true), SESSION_RECORD);

        assertThat(vulnerable.firedFamily("session")).isTrue();
        assertThat(fixed.issues()).isEmpty();
        assertThat(fixed.decisions()).contains("session_binding:peer_denied");
    }

    @Test
    void sessionRebindByAPeerCredentialFiresOnlyWhenTheSessionIsNotOwnerBound() {
        var vulnerable = withPeerB().run(FakeServers.rebindingSessions(false), SESSION_RECORD);
        var fixed = withPeerB().run(FakeServers.rebindingSessions(true), SESSION_RECORD);

        assertThat(vulnerable.issues()).anySatisfy(issue -> {
            assertThat(issue.name()).isEqualTo(SESSION_REBOUND);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.MEDIUM);
        });
        assertThat(fixed.firedFamily("session-rebind")).isFalse();
    }

    @Test
    void rebindingServerNeverReceivesTheIdentitysCredentialOnTheLiveSession() {
        var run = withPeerB().run(FakeServers.rebindingSessions(false), SESSION_RECORD);

        assertThat(run.sent()).noneMatch(SessionBindingCheckTest::peerOnLiveSession);
        assertThat(run.decisions()).contains("session_binding:skipped_rebinding_server");
        assertThat(run.issues()).anySatisfy(issue -> assertThat(issue.name()).isEqualTo(SESSION_REBOUND));
    }

    @Test
    void nonRebindingVulnerableServerStillBindsOnTheLiveSession() {
        var run = withPeerB().run(FakeServers.sessions(false), SESSION_RECORD);

        assertThat(run.sent()).anyMatch(SessionBindingCheckTest::peerOnLiveSession);
        assertThat(run.firedFamily("session")).isTrue();
        assertThat(run.decisions()).doesNotContain("session_binding:skipped_rebinding_server");
    }

    @Test
    void terminatingServerNeverReceivesTheIdentitysCredentialOnTheLiveSession() {
        var run = withPeerB().run(FakeServers.terminatingSessions(false), SESSION_RECORD);

        assertThat(run.sent()).noneMatch(SessionBindingCheckTest::peerOnLiveSession);
        assertThat(run.decisions()).contains("session_binding:skipped_disturbed_session");
    }

    @Test
    void everyIdentityOnAStatefulServerCompletesWithinItsOwnBudget() {
        var harness = new SessionBindingHarness();
        List.of("B", "C", "D").forEach(token -> harness.with(TestPrincipals.peer(token)));

        var run = harness.run(FakeServers.ownerOnlySessions(),
                SESSION_RECORD.withAddedHeader("MCP-Protocol-Version", "2025-11-25"));

        assertThat(run.decisions()).doesNotContain("request_budget_exhausted");
        assertThat(List.of("identity-B", "identity-C", "identity-D"))
                .allSatisfy(identity -> assertThat(run.decisionsOf(identity)).contains("session_binding:peer_denied"));
    }

    @Test
    void identitiesWithoutCredentialsOrWithTheOwnersCredentialsAreNotCompared() {
        var run = new SessionBindingHarness()
                .with(TestPrincipals.identity("N", PrincipalRole.PEER,
                        Map.of(), Optional.empty(), Map.of()))
                .with(TestPrincipals.identity("S", PrincipalRole.PEER,
                        Map.of("Authorization", "Bearer A"), Optional.empty(), Map.of()))
                .run(FakeServers.sessions(false), SESSION_RECORD);

        assertThat(run.sent()).isEmpty();
        assertThat(run.issues()).isEmpty();
    }

    @Test
    void identityDuplicatingAnEarlierIdentitysCredentialsIsNotCompared() {
        var run = withPeerB()
                .with(TestPrincipals.identity("B2", PrincipalRole.PEER,
                        Map.of("Authorization", "Bearer B"), Optional.empty(), Map.of()))
                .run(FakeServers.sessions(false), SESSION_RECORD);

        assertThat(run.sent()).extracting(request -> request.headerValue(ScannerSentinels.IDENTITY_HEADER))
                .contains("b").doesNotContain("b2");
    }

    @Test
    void aSessionlessScanRequestOnAStatefulServerIsProbedInASessionTheCheckOpens() {
        var run = withPeerB().ownerMarker("ALICE-SESSION-RECORD")
                .run(FakeServers.sessions(false), toolCall("read_session_record", "{}", "A"));

        assertThat(run.issues()).filteredOn(issue -> issue.detail().contains("Probe: session."))
                .singleElement().satisfies(issue -> assertThat(issue.name()).isEqualTo(RESULT_AVAILABLE));
    }

    @Test
    void aSessionlessScanRequestOnAServerThatBindsSessionsIsSilent() {
        var run = withPeerB().run(FakeServers.sessions(true), toolCall("read_session_record", "{}", "A"));

        assertThat(run.issues()).isEmpty();
    }

    @Test
    void everySessionOpenedForASessionlessScanRequestIsDeleted() {
        var run = withPeerB().run(FakeServers.sessions(false), toolCall("read_session_record", "{}", "A"));

        List<String> opened = run.sent().stream().filter(request -> !"DELETE".equals(request.method()))
                .map(request -> request.headerValue("Mcp-Session-Id")).filter(java.util.Objects::nonNull).distinct().toList();
        List<String> deleted = run.sent().stream().filter(request -> "DELETE".equals(request.method()))
                .map(request -> request.headerValue("Mcp-Session-Id")).toList();
        assertThat(deleted).containsExactlyInAnyOrderElementsOf(opened);
    }

    @Test
    void statelessRequestsAreNotProbed() {
        var run = withPeerB().run(FakeServers.objectStore(true), toolCall("get_note", "{\"id\":\"a1\"}", "A"));

        assertThat(run.sent()).extracting(request -> FakeMcpTarget.method(request)).containsOnly("initialize");
        assertThat(run.decisions()).containsOnly("session_binding:skipped_stateless_transport");
    }

    @Test
    void everyProbeSessionTheCheckOpenedIsDeletedAndTheLiveSessionNever() {
        var run = withPeerB().run(FakeServers.sessions(false), SESSION_RECORD);

        List<String> used = run.sent().stream().filter(request -> !"DELETE".equals(request.method()))
                .map(request -> request.headerValue("Mcp-Session-Id"))
                .filter(id -> id != null && !id.equals("sess-A")).distinct().toList();
        List<String> deleted = run.sent().stream().filter(request -> "DELETE".equals(request.method()))
                .map(request -> request.headerValue("Mcp-Session-Id")).toList();
        assertThat(used).isNotEmpty();
        assertThat(deleted).containsExactlyInAnyOrderElementsOf(used);
        assertThat(run.sent().subList(run.sent().size() - deleted.size(), run.sent().size()))
                .allMatch(request -> "DELETE".equals(request.method()));
    }

    @Test
    void identityProbesCarryTheirRoutingSentinelAndNeverThePrimarysCredential() {
        var run = withPeerB().run(FakeServers.sessions(false), SESSION_RECORD);

        assertThat(run.sent()).filteredOn(request -> "B".equals(FakeMcpTarget.principal(request)))
                .filteredOn(request -> !"DELETE".equals(request.method()))
                .isNotEmpty()
                .allMatch(request -> "b".equals(request.headerValue(ScannerSentinels.IDENTITY_HEADER)));
        assertThat(run.sent()).filteredOn(request -> "b".equals(
                        request.headerValue(ScannerSentinels.IDENTITY_HEADER)))
                .noneMatch(request -> "Bearer A".equals(request.headerValue("Authorization")));
    }
}
