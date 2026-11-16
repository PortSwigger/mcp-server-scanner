package com.mcpscanner.access.comparison;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mcpscanner.access.mining.AccessMiner;
import com.mcpscanner.access.mining.MiningControl;
import com.mcpscanner.access.mining.MiningReply;
import com.mcpscanner.access.mining.MiningResult;
import com.mcpscanner.access.mining.MiningSender;
import com.mcpscanner.access.mining.MiningSettings;
import com.mcpscanner.checks.api.OwnedObjects;
import com.mcpscanner.identity.OwnedValues;
import com.mcpscanner.mcp.McpObjectMapper;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ToolAnnotations;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.checks.api.crossidentity.FakeMcpTarget;
import com.mcpscanner.checks.api.crossidentity.FakeReply;
import com.mcpscanner.checks.api.crossidentity.FakeServers;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRole;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import static com.mcpscanner.access.comparison.ComparisonHarness.identity;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.principal;
import static com.mcpscanner.checks.api.crossidentity.FakeMcpTarget.toolCall;
import static org.assertj.core.api.Assertions.assertThat;

class AccessComparisonOperationLevelTest {

    private static final String OPERATION = FindingKind.OPERATION_AVAILABLE.issueName();
    private static final String OPERATION_FOR_PEER = FindingKind.OPERATION_AVAILABLE.issueNameFor(PrincipalRole.PEER);
    private static final HttpRequest ADMIN_CALL = toolCall("admin_report", "{}", "A");

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    private static Principal as(String token, PrincipalRole role) {
        return identity(token, role, Map.of("Authorization", "Bearer " + token), Optional.empty(), Map.of());
    }

    private static ComparisonHarness.Run run(AccessExpectation expectation, Principal principal,
                                        Function<HttpRequest, FakeReply> server) {
        return new ComparisonHarness().with(principal).ledger(new RecordingLedger().expecting(expectation))
                .run(server, ADMIN_CALL);
    }

    @ParameterizedTest
    @CsvSource({
            "ANY_SIGNED_IN,LOWER,false", "ANY_SIGNED_IN,PEER,false", "ANY_SIGNED_IN,HIGHER,false",
            "NOT_LOWER,LOWER,true", "NOT_LOWER,PEER,false", "NOT_LOWER,HIGHER,false",
            "OWNER_ONLY,LOWER,true", "OWNER_ONLY,PEER,true", "OWNER_ONLY,HIGHER,true",
            "HIGHER_ONLY,LOWER,true", "HIGHER_ONLY,PEER,true", "HIGHER_ONLY,HIGHER,false",
            "SHARED_BY_DESIGN,LOWER,false", "SHARED_BY_DESIGN,PEER,false", "SHARED_BY_DESIGN,HIGHER,false"})
    void expectationDecidesWhichRolesAreDisallowed(AccessExpectation expectation, PrincipalRole role, boolean fires) {
        var run = run(expectation, as("C", role), FakeServers.adminTool(false));

        assertThat(run.issues().stream().anyMatch(issue -> isOperationFinding(issue.name()))).isEqualTo(fires);
    }

    @ParameterizedTest
    @CsvSource({"NOT_LOWER,LOWER", "OWNER_ONLY,PEER", "HIGHER_ONLY,LOWER"})
    void enforcedOperationIsSilentForEveryDisallowedRole(AccessExpectation expectation, PrincipalRole role) {
        var run = run(expectation, as("C", role), FakeServers.adminTool(true));

        assertThat(run.issues()).isEmpty();
        assertThat(run.ledger().outcomes()).containsEntry("c", AccessOutcome.REFUSED);
    }

    @ParameterizedTest
    @CsvSource({"NOT_LOWER,LOWER,lower privilege", "OWNER_ONLY,PEER,peer", "OWNER_ONLY,HIGHER,higher privilege"})
    void operationFindingNamesTheComparedIdentityWithItsRoleLabel(AccessExpectation expectation, PrincipalRole role,
                                                                  String label) {
        var run = run(expectation, as("C", role), FakeServers.adminTool(false));

        assertThat(run.issues()).singleElement().extracting(issue -> issue.detail()).asString()
                .contains("Identity: identity-C (" + label + ").");
    }

    @Test
    void operationFindingIsHighAndTentativeWhenListedAndUnmarked() {
        var run = run(AccessExpectation.NOT_LOWER, as("C", PrincipalRole.LOWER), FakeServers.adminTool(false));

        assertThat(run.issues()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(OPERATION);
            assertThat(issue.severity()).isEqualTo(AuditIssueSeverity.HIGH);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.TENTATIVE);
        });
    }

    @Test
    void readReplayIsNotDescribedAsRepeatingAStateChange() {
        var run = new ComparisonHarness().with(as("C", PrincipalRole.LOWER))
                .ledger(new RecordingLedger().expecting(AccessExpectation.NOT_LOWER).replayingReads())
                .run(FakeServers.adminTool(false), ADMIN_CALL);

        assertThat(run.issues()).singleElement().extracting(issue -> issue.detail()).asString()
                .contains("replayed as supplied for every arm.").doesNotContain("state-changing");
    }

    @Test
    void confirmedWriteReplayIsDescribedAsRepeatingAStateChange() {
        var run = run(AccessExpectation.NOT_LOWER, as("C", PrincipalRole.LOWER), FakeServers.adminTool(false));

        assertThat(run.issues()).singleElement().extracting(issue -> issue.detail()).asString()
                .contains("so a state-changing operation was repeated.");
    }

    @Test
    void operationFindingIsFirmWhenTheItemIsAbsentFromTheIdentitysOwnListing() {
        var run = new ComparisonHarness().with(as("C", PrincipalRole.LOWER))
                .ledger(new RecordingLedger().expecting(AccessExpectation.NOT_LOWER).listing("c", false))
                .run(FakeServers.adminTool(false), ADMIN_CALL);

        assertThat(run.issues()).singleElement().extracting(issue -> issue.confidence())
                .isEqualTo(AuditIssueConfidence.FIRM);
    }

    @Test
    void operationFindingStaysTentativeWhenTheItemIsListedForTheIdentity() {
        var run = new ComparisonHarness().with(as("C", PrincipalRole.LOWER))
                .ledger(new RecordingLedger().expecting(AccessExpectation.NOT_LOWER).listing("c", true))
                .run(FakeServers.adminTool(false), ADMIN_CALL);

        assertThat(run.issues()).singleElement().extracting(issue -> issue.confidence())
                .isEqualTo(AuditIssueConfidence.TENTATIVE);
    }

    @Test
    void operationFindingIsFirmWhenTheOwnersMarkerAppears() {
        var run = new ComparisonHarness().ownerMarker("ADMIN-EFFECT").with(as("C", PrincipalRole.LOWER))
                .ledger(new RecordingLedger().expecting(AccessExpectation.NOT_LOWER))
                .run(FakeServers.adminTool(false), ADMIN_CALL);

        assertThat(run.issues()).singleElement().extracting(issue -> issue.confidence())
                .isEqualTo(AuditIssueConfidence.FIRM);
    }

    @ParameterizedTest
    @CsvSource({"false", "true"})
    void lowerIdentityRefusedAtTheCapturedVersionButAcceptedAtTheLegacyVersionIsReported(boolean stateful) {
        HttpRequest seed = ADMIN_CALL.withAddedHeader("MCP-Protocol-Version", "2025-11-25");
        HttpRequest base = stateful ? seed.withAddedHeader("Mcp-Session-Id", "sess-A") : seed;
        Function<HttpRequest, FakeReply> server = request -> "initialize".equals(FakeMcpTarget.method(request))
                ? FakeReply.initialized("sess-" + FakeMcpTarget.principal(request))
                : "notifications/initialized".equals(FakeMcpTarget.method(request)) ? FakeReply.accepted()
                : FakeServers.versionDependentScope(false).apply(request);

        var run = new ComparisonHarness().with(as("C", PrincipalRole.LOWER))
                .ledger(new RecordingLedger().expecting(AccessExpectation.NOT_LOWER).listing("c", false))
                .run(server, base);

        assertThat(run.decisions()).contains("peer_replay:peer_denied", "peer_replay:accepted_at_protocol_2024-11-05");
        assertThat(run.issues()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(OPERATION);
            assertThat(issue.confidence()).isEqualTo(AuditIssueConfidence.FIRM);
            assertThat(issue.detail()).contains("2024-11-05");
        });
        assertThat(run.ledger().outcomes()).containsEntry("c", AccessOutcome.SAME_RESULT);
    }

    @ParameterizedTest
    @CsvSource({"ANY_SIGNED_IN,LOWER", "ANY_SIGNED_IN,PEER", "ANY_SIGNED_IN,HIGHER"})
    void identityRefusedAtTheCapturedVersionButAcceptedAtTheLegacyVersionIsReportedWhateverIsExpected(
            AccessExpectation expectation, PrincipalRole role) {
        HttpRequest seed = ADMIN_CALL.withAddedHeader("MCP-Protocol-Version", "2025-11-25");

        var run = new ComparisonHarness().with(as("C", role))
                .ledger(new RecordingLedger().expecting(expectation).listing("c", true))
                .run(FakeServers.versionDependentScope(false), seed);

        assertThat(run.decisions()).contains("peer_replay:accepted_at_protocol_2024-11-05");
        assertThat(run.issues()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(FindingKind.OPERATION_AVAILABLE.issueNameFor(role));
            assertThat(issue.detail()).contains("2024-11-05").contains("refused at the captured protocol version");
            assertThat(issue.detail()).doesNotContain("expectation");
        });
        assertThat(run.ledger().outcomes()).containsEntry("c", AccessOutcome.SAME_RESULT);
    }

    @Test
    void identityRefusedAtEveryProtocolVersionIsNotReportedWhateverIsExpected() {
        HttpRequest seed = ADMIN_CALL.withAddedHeader("MCP-Protocol-Version", "2025-11-25");

        var run = new ComparisonHarness().with(as("C", PrincipalRole.LOWER))
                .ledger(new RecordingLedger().expecting(AccessExpectation.ANY_SIGNED_IN))
                .run(FakeServers.versionDependentScope(true), seed);

        assertThat(run.issues()).isEmpty();
        assertThat(run.ledger().outcomes()).containsEntry("c", AccessOutcome.REFUSED);
    }

    @Test
    void identityAcceptedAtTheLegacyVersionIsNotReportedWhenTheUserDeclaredTheItemShared() {
        HttpRequest seed = ADMIN_CALL.withAddedHeader("MCP-Protocol-Version", "2025-11-25");

        var run = new ComparisonHarness().with(as("C", PrincipalRole.LOWER))
                .ledger(new RecordingLedger().expecting(AccessExpectation.SHARED_BY_DESIGN))
                .run(FakeServers.versionDependentScope(false), seed);

        assertThat(run.issues()).isEmpty();
    }

    @Test
    void lowerIdentityAcceptedAtTheLegacyVersionIsNotReportedWhenAnonymousIsAlsoAccepted() {
        HttpRequest seed = ADMIN_CALL.withAddedHeader("MCP-Protocol-Version", "2025-11-25");

        var run = new ComparisonHarness().with(as("C", PrincipalRole.LOWER))
                .ledger(new RecordingLedger().expecting(AccessExpectation.NOT_LOWER))
                .run(FakeServers.legacyHandlerOpen(), seed);

        assertThat(run.issues()).isEmpty();
        assertThat(run.decisions()).contains("peer_replay:anonymous_success_at_protocol_2024-11-05");
    }

    @Test
    void ownerMarkerInADifferentResultNeverCreatesAnOperationFinding() {
        var run = new ComparisonHarness().ownerMarker("A-PRIVATE-a1").with(as("C", PrincipalRole.LOWER))
                .ledger(new RecordingLedger().expecting(AccessExpectation.NOT_LOWER).listing("c", false))
                .run(FakeServers.peerSeesOwnerMarker(), toolCall("get_note", "{\"id\":\"a1\"}", "A"));

        assertThat(run.issues()).noneMatch(issue -> isOperationFinding(issue.name()));
        assertThat(run.ledger().outcomes()).containsEntry("c", AccessOutcome.DIFFERENT_RESULT);
    }

    @Test
    void verticalFindingSuppressesObjectProbesForThatIdentity() {
        var run = new ComparisonHarness().with(as("B", PrincipalRole.PEER))
                .ledger(new RecordingLedger().expecting(AccessExpectation.OWNER_ONLY))
                .run(FakeServers.objectStore(true), toolCall("get_note", "{\"id\":\"a1\"}", "A"));

        assertThat(run.issues()).singleElement().extracting(issue -> issue.name()).isEqualTo(OPERATION_FOR_PEER);
    }

    @Test
    void sharedByDesignSilencesEveryFindingButStillRecordsOutcomes() {
        var run = new ComparisonHarness().with(as("B", PrincipalRole.PEER))
                .ledger(new RecordingLedger().expecting(AccessExpectation.SHARED_BY_DESIGN))
                .run(FakeServers.objectStore(true), toolCall("get_note", "{\"id\":\"a1\"}", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.ledger().outcomes()).containsEntry("b", AccessOutcome.SAME_RESULT);
    }

    @Test
    void aServerSharedByDesignStaysSilentWhenCollectIdsHasMinedItForBothUsers() {
        Principal owner = withMarker(Principal.PRIMARY_ID, PrincipalRole.PRIMARY, "ALICE_ONLY_MARKER");
        Principal peer = withMarker("b", PrincipalRole.PEER, "BOB_ONLY_MARKER");
        MiningResult mined = new AccessMiner(sharedCampaignsServer(), MiningSettings.defaults())
                .mine(ScanInventory.toolsOnly(List.of(LIST_CAMPAIGNS, GET_TEMPLATE)), List.of(owner, peer),
                        MiningControl.unattended());

        var run = new ComparisonHarness().owner(withMinedValues(owner, mined)).with(withMinedValues(peer, mined))
                .run(FakeServers.sharedTemplates(), toolCall("templates_get", "{\"template_id\":\"t2\"}", "A"));

        assertThat(run.issues()).isEmpty();
        assertThat(run.ledger().findings()).isEmpty();
    }

    private static Principal withMarker(String id, PrincipalRole role, String marker) {
        return new Principal(id, id, role, Map::of, Optional.of(marker), Map.of());
    }

    private static Principal withMinedValues(Principal principal, MiningResult mined) {
        OwnedObjects owned = OwnedValues.of(mined.of(principal.id()).orElseThrow().values())
                .ownerArguments();
        return new Principal(principal.id(), principal.name(), principal.role(), () -> Map.of("Authorization",
                "Bearer " + (principal.role() == PrincipalRole.PRIMARY ? "A" : "B")), principal.privateMarker(), owned,
                null);
    }

    private static MiningSender sharedCampaignsServer() {
        String everything = "{\"campaigns\":[{\"id\":\"c-a\",\"name\":\"ALICE_ONLY_MARKER BOB_ONLY_MARKER\","
                + "\"template_id\":\"t1\"},{\"id\":\"c-b\",\"name\":\"BOB_ONLY_MARKER\",\"template_id\":\"t1\"}]}";
        return (identity, call) -> {
            ObjectNode result = McpObjectMapper.INSTANCE.createObjectNode();
            try {
                result.set("structuredContent", McpObjectMapper.INSTANCE.readTree(everything));
            } catch (Exception malformed) {
                throw new IllegalStateException(malformed);
            }
            return MiningReply.of(200, result);
        };
    }

    private static final McpToolDefinition LIST_CAMPAIGNS = readOnly("campaigns_list",
            "{\"type\":\"object\",\"properties\":{}}");
    private static final McpToolDefinition GET_TEMPLATE = readOnly("templates_get",
            "{\"type\":\"object\",\"properties\":{\"template_id\":{\"type\":\"string\"}}}");

    private static McpToolDefinition readOnly(String name, String inputSchema) {
        return new McpToolDefinition(name, "", inputSchema, List.of(),
                new ToolAnnotations(null, true, null, null, null));
    }

    @Test
    void higherIdentityIsNeverObjectCompared() {
        var run = new ComparisonHarness().with(as("H", PrincipalRole.HIGHER))
                .run(FakeServers.objectStore(true), toolCall("get_note", "{\"id\":\"a1\"}", "A"));

        assertThat(run.issues()).isEmpty();
    }

    @Test
    void higherOnlyItemOwnedByAHigherIdentityReportsThePrimary() {
        Principal higher = as("H", PrincipalRole.HIGHER);
        Function<HttpRequest, FakeReply> server = FakeServers.authenticated(request -> "C".equals(principal(request))
                ? FakeReply.toolError("insufficient scope") : FakeReply.result("ADMIN-EFFECT report"));

        Principal alice = new Principal(Principal.PRIMARY_ID, "alice", PrincipalRole.PRIMARY,
                () -> Map.of("Authorization", "Bearer A"), Optional.empty(), Map.of());

        var run = new ComparisonHarness().owner(alice).with(higher).with(as("C", PrincipalRole.LOWER)).auditAs(higher)
                .ledger(new RecordingLedger().expecting(AccessExpectation.HIGHER_ONLY))
                .run(server, toolCall("admin_report", "{}", "H"));

        assertThat(run.issues()).singleElement().satisfies(issue -> {
            assertThat(issue.name()).isEqualTo(OPERATION);
            assertThat(issue.detail()).contains("Identity: alice (Primary user)").doesNotContain("primary");
        });
        assertThat(run.ledger().outcomes()).containsEntry(Principal.PRIMARY_ID, AccessOutcome.SAME_RESULT)
                .containsEntry("c", AccessOutcome.REFUSED).doesNotContainKey("h");
    }

    @Test
    void anonymousServedAsAnIdentityBlocksTheVerticalFinding() {
        var run = new ComparisonHarness().with(as("B", PrincipalRole.PEER))
                .ledger(new RecordingLedger().expecting(AccessExpectation.OWNER_ONLY))
                .run(FakeServers.processWideCache(), toolCall("list_orgs", "{}", "A").withAddedHeader("Mcp-Session-Id", "sess-A"));

        assertThat(run.issues()).noneMatch(issue -> isOperationFinding(issue.name()));
    }

    private static boolean isOperationFinding(String name) {
        return name.equals(OPERATION) || name.equals(OPERATION_FOR_PEER);
    }
}
