package com.mcpscanner.integration;

import com.mcpscanner.access.AccessCell;
import com.mcpscanner.checks.api.AccessFinding;

import com.mcpscanner.access.AccessRow;
import com.mcpscanner.access.AccessRunSummary;
import com.mcpscanner.access.AccessSnapshot;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.util.List;

import static com.mcpscanner.integration.CheckAccessFixture.ALICE;
import static com.mcpscanner.integration.CheckAccessFixture.BOB;
import static com.mcpscanner.integration.CheckAccessFixture.CAROL;
import static com.mcpscanner.integration.CheckAccessFixture.HANDBOOK;
import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfEnvironmentVariable(named = "MCP_E2E_IT", matches = "1")
class CheckAccessRunnerIT {

    private static final AccessItemKey GET_DOCUMENT = new AccessItemKey(AccessItemKey.Kind.TOOL, "get_document");
    private static final AccessItemKey DELETE_PROJECT = new AccessItemKey(AccessItemKey.Kind.TOOL, "delete_project");
    private static final AccessItemKey LIST_USERS = new AccessItemKey(AccessItemKey.Kind.TOOL, "list_users");
    private static final AccessItemKey ALICE_NOTE = new AccessItemKey(AccessItemKey.Kind.RESOURCE,
            "notes://alice/private.md");
    private static final AccessItemKey BOB_NOTE = new AccessItemKey(AccessItemKey.Kind.RESOURCE,
            "notes://bob/private.md");

    @BeforeEach
    void installMontoya() {
        MontoyaTestFactory.install();
    }

    @Test
    void vulnerableServerFillsTheMatrixWithAnomaliesWhereIdentitiesReachWhatTheyShouldNot() throws Exception {
        AccessSnapshot snapshot = checkAccess("vulnerable");

        assertThat(row(snapshot, GET_DOCUMENT).cell(BOB.id()).outcome()).contains(AccessOutcome.SAME_RESULT);
        AccessCell bobReadsAlicesDocument = row(snapshot, GET_DOCUMENT).cell(BOB.id());
        assertThat(bobReadsAlicesDocument.findings()).extracting(AccessFinding::summary).containsExactlyInAnyOrder(
                "Object-level: bob received alice's private marker",
                "Object-level: alice's credentials reached bob's object (Firm — bob's private marker appeared)");
        assertThat(bobReadsAlicesDocument.reported()).isTrue();
        assertThat(bobReadsAlicesDocument.possible()).isFalse();
        assertThat(bobReadsAlicesDocument.anomaly()).isFalse();
        assertThat(row(snapshot, DELETE_PROJECT).expectation()).isEqualTo(AccessExpectation.NOT_LOWER);
        assertThat(row(snapshot, DELETE_PROJECT).cell(CAROL.id()).outcome()).contains(AccessOutcome.SAME_RESULT);
        assertThat(row(snapshot, DELETE_PROJECT).cell(CAROL.id()).anomaly()).isTrue();
        assertThat(row(snapshot, DELETE_PROJECT).cell(BOB.id()).anomaly()).isFalse();
        for (AccessItemKey ownerOnly : List.of(LIST_USERS, ALICE_NOTE)) {
            AccessRow row = row(snapshot, ownerOnly);
            assertThat(row.expectation()).isEqualTo(AccessExpectation.OWNER_ONLY);
            assertThat(row.cell(BOB.id()).anomaly()).as(ownerOnly + " as bob").isTrue();
            assertThat(row.cell(CAROL.id()).anomaly()).as(ownerOnly + " as carol").isTrue();
            assertThat(row.anonymous().outcome()).contains(AccessOutcome.REFUSED);
        }
        assertThat(row(snapshot, BOB_NOTE).owner()).isEqualTo(BOB);
        assertThat(row(snapshot, BOB_NOTE).cell(ALICE.id()).anomaly()).isTrue();
        assertThat(row(snapshot, BOB_NOTE).cell(CAROL.id()).anomaly()).isTrue();
        assertThat(row(snapshot, HANDBOOK).anomalies()).isZero();
    }

    @Test
    void safeServerFillsTheMatrixWithoutAnomalies() throws Exception {
        AccessSnapshot snapshot = checkAccess("safe");

        assertThat(row(snapshot, GET_DOCUMENT).cell(BOB.id()).outcome()).contains(AccessOutcome.REFUSED);
        assertThat(row(snapshot, DELETE_PROJECT).cell(CAROL.id()).outcome()).contains(AccessOutcome.REFUSED);
        assertThat(row(snapshot, LIST_USERS).cell(BOB.id()).outcome()).contains(AccessOutcome.REFUSED);
        assertThat(row(snapshot, ALICE_NOTE).cell(CAROL.id()).outcome()).contains(AccessOutcome.REFUSED);
        assertThat(row(snapshot, BOB_NOTE).cell(ALICE.id()).outcome()).contains(AccessOutcome.REFUSED);
        assertThat(snapshot.anomalies()).isZero();
    }

    @Test
    void aComparedUserAddedAfterConnectGetsTheSameItemsAndIssuesAutomaticallyAsAfterClickingDiscover()
            throws Exception {
        AccessRunSummary neverDiscovered = checkAccessWithLateBob(CheckAccessFixture.LateComparedUser.NEVER_DISCOVERED);
        AccessRunSummary discoverClicked = checkAccessWithLateBob(CheckAccessFixture.LateComparedUser.DISCOVER_CLICKED);
        AccessRunSummary automatic = checkAccessWithLateBob(
                CheckAccessFixture.LateComparedUser.DISCOVERED_AUTOMATICALLY);

        System.out.println("round-1 repro, alice+bob Bearer, HTTP 2025 (session): never discovered = "
                + neverDiscovered.total() + " items " + neverDiscovered.issues() + " issues, Discover clicked = "
                + discoverClicked.total() + " items " + discoverClicked.issues() + " issues, discovered "
                + "automatically = " + automatic.total() + " items " + automatic.issues() + " issues");
        assertThat(neverDiscovered.issues()).isZero();
        assertThat(discoverClicked.issues()).isPositive();
        assertThat(automatic.total()).isEqualTo(discoverClicked.total()).isGreaterThan(neverDiscovered.total());
        assertThat(automatic.issues()).isEqualTo(discoverClicked.issues());
    }

    private AccessRunSummary checkAccessWithLateBob(CheckAccessFixture.LateComparedUser lateUser) throws Exception {
        try (McpCheckItSupport.RunningServer server = McpCheckItSupport.startServer();
             CheckAccessFixture access = CheckAccessFixture.prepareWithComparedUserAddedAfterConnect(
                     McpCheckItSupport.mcpEndpoint(server.port()), lateUser)) {
            access.checkEveryItem();
            return access.lastSummary();
        }
    }

    private AccessSnapshot checkAccess(String mode) throws Exception {
        try (McpCheckItSupport.RunningServer server = CheckAccessFixture.startServer(mode);
             CheckAccessFixture access = CheckAccessFixture.prepare(McpCheckItSupport.mcpEndpoint(server.port()))) {
            return access.checkAllItems();
        }
    }

    private static AccessRow row(AccessSnapshot snapshot, AccessItemKey key) {
        return snapshot.rows().stream().filter(row -> row.item().key().equals(key)).findFirst()
                .orElseThrow(() -> new AssertionError("no row for " + key + " in " + snapshot.rows().stream()
                        .map(row -> row.item().key().name()).toList()));
    }
}
