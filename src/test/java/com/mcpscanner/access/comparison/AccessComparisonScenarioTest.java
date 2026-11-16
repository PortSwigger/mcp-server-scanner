package com.mcpscanner.access.comparison;

import com.mcpscanner.checks.api.crossidentity.FakeMcpTarget;
import com.mcpscanner.checks.api.crossidentity.FakeReply;
import com.mcpscanner.checks.api.crossidentity.FakeServers;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.AccessFinding;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.CheckServices;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static com.mcpscanner.access.comparison.ComparisonHarness.identity;
import static com.mcpscanner.access.comparison.ComparisonHarness.withPeerB;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.resourceRead;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.toolCall;
import static org.assertj.core.api.Assertions.assertThat;

class AccessComparisonScenarioTest {

    private static final String RESULT_AVAILABLE = FindingKind.RESULT_AVAILABLE.issueName();

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    private static HttpRequest inSession(HttpRequest seed, String session) {
        return seed.withAddedHeader("Mcp-Session-Id", session);
    }

    private static ComparisonHarness lowerC() {
        return new ComparisonHarness().ownerMarker("ADMIN-EFFECT")
                .with(identity("C", PrincipalRole.LOWER, Map.of("Authorization", "Bearer C"), Optional.empty(), Map.of()))
                .ledger(new RecordingLedger().expecting(AccessExpectation.NOT_LOWER));
    }

    private static ComparisonHarness owning(String owned, String marker, Map<String, String> objects) {
        return new ComparisonHarness().with(identity("B", PrincipalRole.PEER, Map.of("Authorization", "Bearer B"),
                Optional.ofNullable(marker), objects));
    }

    @Test
    void downgradesAreTriedOnlyAfterADenial() {
        HttpRequest seed = toolCall("list_my_notes", "{}", "A").withAddedHeader("MCP-Protocol-Version", "2025-11-25");

        var run = withPeerB().run(FakeServers.whoami(), seed);

        assertThat(run.sent()).filteredOn(request -> "B".equals(FakeMcpTarget.principal(request)))
                .isNotEmpty()
                .allMatch(request -> "2025-11-25".equals(request.headerValue("MCP-Protocol-Version")));
    }

    @Test
    void ownedValuesWithoutAHandEnteredPrivateMarkerOnlyEverMakeAPossibleFindingOnTheGrid() {
        var run = owning("B", null, Map.of("vault", "tenantb", "path", "b.md"))
                .run(FakeServers.vaults(false), toolCall("read_note", "{\"vault\":\"main\",\"path\":\"n.md\"}", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.ledger().findingsOf("b")).singleElement().satisfies(finding -> {
            assertThat(finding.kind()).isEqualTo(AccessFinding.Kind.POSSIBLE_OBJECT_LEVEL);
            assertThat(finding.summary()).isEqualTo("Object-level: Primary's credentials reached identity-B's object "
                    + "(Tentative — no private marker configured for identity-B)");
        });
    }

    @Test
    void resourceListedToTheIdentityRaisesNoObjectFinding() {
        var run = withPeerB().ledger(new RecordingLedger().listing("b", true))
                .run(FakeServers.notes(), resourceRead("notes://team/handbook.md", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.decisions()).contains("object_level:resource_listed_to_identity");
        assertThat(run.ledger().outcomes()).containsEntry("b", AccessOutcome.SAME_RESULT);
    }

    @Test
    void resourceListedToTheIdentityStillFiresWhenItReturnsTheOwnersMarker() {
        var run = withPeerB().ownerMarker("ALICE-NOTE").ledger(new RecordingLedger().listing("b", true))
                .run(FakeServers.notes(), resourceRead("notes://alice/private.md", "A"));

        assertThat(run.issues()).hasSize(1);
    }

    @Test
    void sharedResourceListedToTheIdentityStaysSilentWhenItLacksTheOwnersMarker() {
        var run = withPeerB().ownerMarker("ALICE-NOTE").ledger(new RecordingLedger().listing("b", true))
                .run(FakeServers.notes(), resourceRead("notes://team/handbook.md", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.ledger().findingsOf("b")).isEmpty();
    }

    @Test
    void leakingResourceListedToTheIdentityWithoutAMarkerStaysSilent() {
        var run = withPeerB().ledger(new RecordingLedger().listing("b", true))
                .run(FakeServers.notes(), resourceRead("notes://alice/private.md", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.ledger().findingsOf("b")).isEmpty();
    }

    @Test
    void resourceHiddenFromTheIdentityStillFires() {
        var hidden = withPeerB().ownerMarker("ALICE-NOTE").ledger(new RecordingLedger().listing("b", false))
                .run(FakeServers.notes(), resourceRead("notes://alice/private.md", "A"));
        var unknown = withPeerB().ownerMarker("ALICE-NOTE").run(FakeServers.notes(), resourceRead("notes://alice/private.md", "A"));

        assertThat(hidden.issues()).hasSize(1);
        assertThat(unknown.issues()).hasSize(1);
    }

    @Test
    void toolsListedToTheIdentityAreStillObjectCompared() {
        var run = withPeerB().ownerMarker("A-PRIVATE-a1").ledger(new RecordingLedger().listing("b", true))
                .run(FakeServers.objectStore(true), toolCall("get_note", "{\"id\":\"a1\"}", "A"));

        assertThat(run.issues()).hasSize(1);
    }


    @Test
    void onlyToolCallsAndResourceReadsWithAnIdApply() {
        var list = withPeerB().run(FakeServers.open(), FakeMcpTarget.request(
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}", "A"));
        var notification = withPeerB().run(FakeServers.open(), FakeMcpTarget.request(
                "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"x\"}}", "A"));
        var get = withPeerB().run(FakeServers.open(), FakeMcpTarget.toolCall("get_note", "{}", "A").withMethod("GET"));

        assertThat(list.sent()).isEmpty();
        assertThat(notification.sent()).isEmpty();
        assertThat(get.sent()).isEmpty();
    }

    @Test
    void withoutComparedIdentitiesNothingIsSent() {
        var run = new ComparisonHarness().run(FakeServers.objectStore(false), toolCall("get_note", "{\"id\":\"a1\"}", "A"));

        assertThat(run.sent()).isEmpty();
        assertThat(run.decisions()).contains("no_peer_profile");
    }

    @Test
    void identityWithoutLiveCredentialsIsNotCompared() {
        var run = new ComparisonHarness().with(identity("B", PrincipalRole.PEER, Map.of(), Optional.empty(), Map.of()))
                .run(FakeServers.objectStore(true), toolCall("get_note", "{\"id\":\"a1\"}", "A"));

        assertThat(run.sent()).isEmpty();
        assertThat(run.decisions()).contains("no_peer_profile");
    }

    @Test
    void ownerMarkerMakesTheFindingHighAndFirm() {
        var run = withPeerB().ownerMarker("A-PRIVATE-a1").run(FakeServers.objectStore(true),
                toolCall("get_note", "{\"id\":\"a1\"}", "A"));

        assertThat(run.issues()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(RESULT_AVAILABLE);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        });
        assertThat(run.firedFamily("private-marker")).isTrue();
        assertThat(run.ledger().findingsOf("b")).singleElement().satisfies(finding -> {
            assertThat(finding.kind()).isEqualTo(AccessFinding.Kind.OBJECT_LEVEL);
            assertThat(finding.summary()).isEqualTo("Object-level: identity-B received Primary's private marker");
        });
    }

    @Test
    void anOwnerMarkerThatDoesNotAppearLeavesThePeerReplayPossible() {
        var run = withPeerB().ownerMarker("NOT-IN-THE-NOTE").run(FakeServers.objectStore(true),
                toolCall("get_note", "{\"id\":\"a1\"}", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.ledger().findingsOf("b")).isEmpty();
        assertThat(run.ledger().outcomes()).containsEntry("b", AccessOutcome.SAME_RESULT);
    }

    @Test
    void ownerCheckedObjectIsSilentAndNeverCompared() {
        var run = withPeerB().run(FakeServers.objectStore(false), toolCall("get_note", "{\"id\":\"a1\"}", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.ledger().outcomes()).containsEntry("b", AccessOutcome.REFUSED);
    }

    @Test
    void perPrincipalResultIsSilent() {
        var run = withPeerB().run(FakeServers.whoami(), toolCall("list_my_notes", "{\"limit\":5}", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.ledger().outcomes()).containsEntry("b", AccessOutcome.DIFFERENT_RESULT);
    }

    @Test
    void globalToolWithoutAMarkerIsSilent() {
        var run = withPeerB().run(FakeServers.global(), toolCall("server_info", "{}", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.ledger().findingsOf("b")).isEmpty();
    }

    @Test
    void legacyProtocolScopeBypassIsFoundAfterADenialAtTheCapturedVersion() {
        HttpRequest seed = toolCall("admin_report", "{}", "A").withAddedHeader("MCP-Protocol-Version", "2025-11-25");

        var vulnerable = lowerC().run(FakeServers.versionDependentScope(false), seed);
        var fixed = lowerC().run(FakeServers.versionDependentScope(true), seed);

        assertThat(vulnerable.issues()).hasSize(1);
        assertThat(vulnerable.decisions()).contains("peer_replay:accepted_at_protocol_2024-11-05");
        assertThat(fixed.issues()).isEmpty();
        assertThat(fixed.decisions()).filteredOn("peer_replay:peer_denied"::equals).hasSize(3);
    }

    @Test
    void anonymousSuccessWithTheOwnersResultDefersToUnauthenticatedRequestExecution() {
        var run = withPeerB().run(FakeServers.open(), toolCall("get_note", "{\"id\":\"a1\"}", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.decisions()).contains("anonymous_operation_success");
    }

    @Test
    void anonymousServedAsThePeerContinuesAndNeverReportsTheSessionIdAsACredential() {
        var run = withPeerB().run(FakeServers.processWideCache(), inSession(toolCall("list_orgs", "{}", "A"), "sess-A"));

        assertThat(run.decisions()).doesNotContain("anonymous_operation_success");
        assertThat(run.issues()).allMatch(issue -> issue.name().equals(RESULT_AVAILABLE));
    }

    @Test
    void anonymousOtherResultWithoutAPeerWitnessStops() {
        var run = withPeerB().run(FakeServers.unauthenticatedSessionEcho(),
                inSession(toolCall("read_session_record", "{}", "A"), "sess-A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.decisions()).contains("anonymous_operation_success");
    }

    @Test
    void markerCopiedFromTheRequestNeverConfirms() {
        var run = withPeerB().ownerMarker("SECRET-ROW").run(FakeServers.echo(),
                toolCall("run_sql", "{\"sql\":\"select 'SECRET-ROW'\"}", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.ledger().findingsOf("b")).isEmpty();
    }

    @Test
    void emptyOwnerResultStops() {
        var run = withPeerB().run(FakeServers.emptyInbox(), toolCall("get_inbox", "{\"folder\":\"inbox\"}", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.decisions()).contains("baseline_unusable");
    }

    @Test
    void downgradedAnonymousSuccessStops() {
        HttpRequest seed = toolCall("admin_report", "{}", "A").withAddedHeader("MCP-Protocol-Version", "2025-11-25");

        var run = lowerC().run(FakeServers.legacyHandlerOpen(), seed);

        assertThat(run.issues()).isEmpty();
        assertThat(run.decisions()).contains("peer_replay:anonymous_success_at_protocol_2024-11-05");
    }

    @Test
    void emptyJsonListResultStopsAtTheBaseline() {
        var run = withPeerB().run(FakeServers.authenticated(request -> FakeReply.result(
                "{\\\"data\\\":[],\\\"total\\\":0,\\\"offset\\\":0}")), toolCall("list_contacts", "{\"limit\":5}", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.decisions()).contains("baseline_unusable");
    }

    @Test
    void sessionBindingIsLeftToItsOwnCheck() {
        var run = withPeerB().run(FakeServers.sessions(false), inSession(toolCall("read_session_record", "{}", "A"),
                "sess-A"));

        assertThat(run.decisions()).noneMatch(decision -> decision.startsWith("session_"));
        assertThat(run.sent()).noneMatch(AccessComparisonScenarioTest::peerOnLiveSession);
        assertThat(run.issues()).isEmpty();
    }

    private static boolean peerOnLiveSession(HttpRequest request) {
        return "sess-A".equals(request.headerValue("Mcp-Session-Id")) && "B".equals(FakeMcpTarget.principal(request));
    }

    @Test
    void foreignReferenceFiresWithAPositiveWitnessAndAFullCoordinate() {
        HttpRequest seed = toolCall("read_note", "{\"vault\":\"main\",\"path\":\"n.md\"}", "A");

        var vulnerable = owning("B", "TENANT-B", Map.of("vault", "tenantb", "path", "b.md"))
                .run(FakeServers.vaults(false), seed);
        var fixed = owning("B", "TENANT-B", Map.of("vault", "tenantb", "path", "b.md"))
                .run(FakeServers.vaults(true), seed);
        var partial = owning("B", "TENANT-B", Map.of("vault", "tenantb")).run(FakeServers.vaults(false), seed);
        var absent = owning("B", "TENANT-B", Map.of("vault", "tenantb", "path", "b.md"))
                .run(FakeServers.vaults(false), toolCall("read_note", "{\"path\":\"n.md\"}", "A"));

        assertThat(vulnerable.issues()).singleElement().satisfies(issue -> {
            assertThat(issue.detail()).contains("Probe: foreign-reference.");
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
        });
        assertThat(fixed.issues()).isEmpty();
        assertThat(fixed.decisions()).contains("foreign_reference:denied");
        assertThat(partial.issues()).isEmpty();
        assertThat(partial.decisions()).contains("foreign_reference:denied");
        assertThat(absent.issues()).isEmpty();
    }

    @Test
    void foreignReferenceUsesTheOwnedValuesTheItemTakesAndIgnoresValuesMinedForOtherTools() {
        HttpRequest seed = toolCall("read_note", "{\"vault\":\"main\",\"path\":\"n.md\"}", "A");

        var run = owning("B", "TENANT-B", Map.of("vault", "tenantb", "path", "b.md", "project_id", "p-77"))
                .run(FakeServers.vaults(false), seed);

        assertThat(run.firedFamily("foreign-reference")).isTrue();
    }

    @Test
    void foreignReferenceSubstitutesOnlyTheValuesTheReferencePortAllowsForTheItem() {
        HttpRequest seed = toolCall("read_note", "{\"vault\":\"main\",\"path\":\"n.md\"}", "A");
        java.util.List<String> askedFor = new java.util.ArrayList<>();

        var run = owning("B", "TENANT-B", Map.of("vault", "tenantb", "path", "b.md"))
                .references((principal, item) -> {
                    askedFor.add(principal.name() + " " + item.name());
                    return Map.of();
                })
                .run(FakeServers.vaults(false), seed);

        assertThat(run.firedFamily("foreign-reference")).isFalse();
        assertThat(run.decisions()).contains("foreign_reference:absent");
        assertThat(askedFor).isNotEmpty().allMatch(asked -> asked.endsWith(" read_note"));
    }

    @Test
    void foreignResourceUriFiresOnlyWhenNotOwnerChecked() {
        HttpRequest seed = resourceRead("file://flows/a/report.txt", "A");
        Map<String, String> owned = Map.of("uri", "file://flows/b/report.txt");

        var vulnerable = owning("B", "B-FILE", owned).run(FakeServers.files(false), seed);
        var fixed = owning("B", "B-FILE", owned).run(FakeServers.files(true), seed);

        assertThat(vulnerable.firedFamily("foreign-reference")).isTrue();
        assertThat(fixed.issues()).isEmpty();
        assertThat(fixed.decisions()).contains("foreign_reference:denied");
    }

    @Test
    void nestedForeignReferenceNeedsAWitnessAndADenialAsContentIsNotOne() {
        HttpRequest seed = toolCall("readAttachment", "{\"files\":[{\"title\":\"a\",\"path\":\"a/report.txt\"}]}", "A");
        Map<String, String> owned = Map.of("files[0].path", "b/report.txt");

        var vulnerable = owning("B", "B-FILE", owned).run(FakeServers.attachments(false), seed);
        var fixed = owning("B", "B-FILE", owned).run(FakeServers.attachments(true), seed);

        assertThat(vulnerable.firedFamily("foreign-reference")).isTrue();
        assertThat(fixed.issues()).isEmpty();
        assertThat(fixed.decisions()).contains("foreign_reference:no_positive_witness");
    }

    @Test
    void foreignMarkerEchoedFromTheSubstitutedRequestNeverConfirms() {
        var run = owning("B", "bob/notes.md", Map.of("path", "bob/notes.md"))
                .run(FakeServers.pathEchoRefusal(), toolCall("read_note", "{\"path\":\"alice/notes.md\"}", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.decisions()).contains("foreign_reference:no_positive_witness");
    }

    @Test
    void embeddedResourceContentIsSubstantive() {
        var run = withPeerB().run(FakeServers.embeddedResourceStore(), toolCall("get_doc", "{\"id\":\"a1\"}", "A"));

        assertThat(run.ledger().outcomes()).containsEntry("b", AccessOutcome.SAME_RESULT);
    }

    @Test
    void identityHeadersReplaceEveryCapturedCredential() {
        HttpRequest seed = toolCall("get_note", "{\"id\":\"a1\"}", "A").withAddedHeader("X-Tenant-Key", "key-A");

        var run = new ComparisonHarness().with(identity("B", PrincipalRole.PEER, Map.of("X-Tenant-Key", "key-B"),
                Optional.empty(), Map.of())).run(FakeServers.objectStore(true), seed);

        assertThat(run.sent()).anyMatch(request -> "key-B".equals(request.headerValue("X-Tenant-Key"))
                && request.headerValue("Authorization") == null);
    }
}
