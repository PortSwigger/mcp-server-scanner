package com.mcpscanner;

import com.mcpscanner.access.AccessRow;
import com.mcpscanner.access.AccessRunListener;
import com.mcpscanner.access.AccessRunSummary;
import com.mcpscanner.access.AccessSnapshot;
import com.mcpscanner.access.CheckAccessRunner;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.OwnedValues;
import com.mcpscanner.identity.discovery.DiscoveryOutcome;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.StreamingCampaignServer;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static com.mcpscanner.WiredExtension.RUN_BOUND;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class CheckAccessOnStreamingServerWiringTest {

    private static final AccessItemKey CAMPAIGNS_GET =
            new AccessItemKey(AccessItemKey.Kind.TOOL, StreamingCampaignServer.TOOL);

    private StreamingCampaignServer server;
    private WiredExtension extension;

    @BeforeEach
    void setUp() throws Exception {
        MontoyaTestFactory.install();
        server = StreamingCampaignServer.vulnerable();
        extension = WiredExtension.sendingThroughTheJdkClient();
    }

    @AfterEach
    void unload() {
        extension.close();
        server.close();
    }

    @Test
    void checkAccessFillsTheCellsAndReportsTheCrossUserCampaignWhenTheServerStreamsItsReplies() {
        connectAsAliceComparingBob();

        AccessRunSummary summary = checkAccess(extension.access().matrix().snapshot().rows());

        assertThat(warnings()).isEmpty();
        assertThat(summary.issues()).isPositive();
        assertThat(campaignsGetRow().cell(bobId()).outcome()).contains(AccessOutcome.SAME_RESULT);
        assertThat(extension.siteMap()).extracting(AuditIssue::name)
                .contains("MCP operation result available to another principal");
    }

    @Test
    void checkAccessRunAgainConsolidatesIntoTheIssuesTheFirstRunFiled() {
        connectAsAliceComparingBob();
        checkAccess(extension.access().matrix().snapshot().rows());
        List<AuditIssue> firstRun = List.copyOf(extension.siteMap());

        AccessRunSummary rerun = checkAccess(extension.access().matrix().snapshot().rows());

        assertThat(rerun.issues()).isPositive();
        assertThat(extension.siteMap()).containsExactlyElementsOf(firstRun);
    }

    @Test
    void extensionScanOfTheToolLeavesCrossUserTestingToCheckAccess() {
        connectAsAliceComparingBob();

        extension.scanTool(campaignsGetRow().item().tool().orElseThrow());

        assertThat(extension.logged()).noneMatch(message -> message.contains("Streaming response received"));
        assertThat(extension.siteMap()).extracting(AuditIssue::name)
                .doesNotContain("MCP operation result available to another principal");
    }

    private void connectAsAliceComparingBob() {
        IdentityRegistry registry = extension.foundation().identities();
        registry.update(registry.primaryUser()
                .withOwnedValues(OwnedValues.entered(Map.of("id", StreamingCampaignServer.ALICE_CAMPAIGN)))
                .withPrivateMarker(StreamingCampaignServer.ALICE_MARKER));
        Identity bob = registry.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER)
                .withOwnedValues(OwnedValues.entered(Map.of("id", StreamingCampaignServer.BOB_CAMPAIGN)))
                .withPrivateMarker(StreamingCampaignServer.BOB_MARKER));
        registry.setCredential(bob.id(), new BearerTokenAuthStrategy(StreamingCampaignServer.BOB_TOKEN));
        BearerTokenAuthStrategy alice = new BearerTokenAuthStrategy(StreamingCampaignServer.ALICE_TOKEN);
        extension.access().authHolder().set(alice);
        extension.connection().clientManager().connect(new McpServerConfig(server.endpoint(),
                TransportType.STREAMABLE_HTTP, alice));
        await().atMost(RUN_BOUND).until(() -> listed(Principal.PRIMARY_ID) && listed(bob.id()));
    }

    private boolean listed(String principalId) {
        return extension.identityDiscovery().listings().outcome(principalId).filter(DiscoveryOutcome.Listed.class::isInstance)
                .isPresent();
    }

    private AccessRunSummary checkAccess(List<AccessRow> rows) {
        CheckAccessRunner runner = extension.access().runner(extension.connection(), extension.scanning());
        CompletableFuture<AccessRunSummary> finished = new CompletableFuture<>();
        runner.start(rows, tools -> true, new AccessRunListener() {
            @Override
            public void progress(int done, int total) {
            }

            @Override
            public void finished(AccessRunSummary summary) {
                finished.complete(summary);
            }
        }).orElseThrow();
        await().atMost(RUN_BOUND).until(finished::isDone);
        return finished.join();
    }

    private AccessRow campaignsGetRow() {
        AccessSnapshot snapshot = extension.access().matrix().snapshot();
        return snapshot.rows().stream().filter(row -> row.item().key().equals(CAMPAIGNS_GET)).findFirst()
                .orElseThrow();
    }

    private String bobId() {
        return extension.foundation().identities().otherUsers().get(0).id();
    }

    private List<String> warnings() {
        return extension.logEntries().stream()
                .filter(entry -> entry.level() == McpEventLog.Level.WARN)
                .map(McpEventLog.LogEntry::message).toList();
    }
}
