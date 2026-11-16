package com.mcpscanner.ui;

import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.access.AccessFixtures;
import com.mcpscanner.access.AccessMatrix;
import com.mcpscanner.access.AccessRuns;
import com.mcpscanner.access.MatrixAccessLedger;
import com.mcpscanner.access.WriteReplays;
import com.mcpscanner.access.CheckAccessRunner;
import com.mcpscanner.access.IdentityRequests;
import com.mcpscanner.access.OwnerRequests;
import com.mcpscanner.access.RecordingComparison;
import com.mcpscanner.access.RecordingHttp;
import com.mcpscanner.access.WriteReplayConfirmations;
import com.mcpscanner.checks.api.AccessFinding;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.request.GeneratedScan;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.testutil.SwingTree;
import com.mcpscanner.ui.access.AccessPanel;
import com.mcpscanner.ui.widgets.HyperlinkLabel;
import com.mcpscanner.ui.access.AccessServices;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.stream.IntStream;

import static com.mcpscanner.access.AccessFixtures.ALICE;
import static com.mcpscanner.access.AccessFixtures.BOB;
import static com.mcpscanner.access.AccessFixtures.tool;
import static com.mcpscanner.access.AccessFixtures.toolKey;
import static com.mcpscanner.ui.McpScannerTabFixture.click;
import static com.mcpscanner.ui.McpScannerTabFixture.destructiveTool;
import static com.mcpscanner.ui.McpScannerTabFixture.drawer;
import static com.mcpscanner.ui.McpScannerTabFixture.find;
import static com.mcpscanner.ui.McpScannerTabFixture.flushEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.fromEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.inventory;
import static com.mcpscanner.ui.McpScannerTabFixture.onEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.scanButton;
import static com.mcpscanner.ui.McpScannerTabFixture.tools;
import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;

class McpScannerTabAccessTest {

    private final McpScannerTabFixture fixture = new McpScannerTabFixture();
    private final AccessRuns runs = new AccessRuns(Executors.newSingleThreadExecutor());
    private final AccessFixtures identities = new AccessFixtures().compare(BOB)
            .lists(ALICE, List.of(tool("delete")), List.of())
            .lists(BOB, List.of(), List.of());
    private final AccessMatrix matrix = identities.matrix();
    private final WriteReplayConfirmations confirmations = new WriteReplayConfirmations();

    @AfterEach
    void stop() {
        runs.shutdown();
    }

    @Test
    void accessTabFollowsTheInventoryTabsAndCountsIssuesInItsTitle() throws Exception {
        McpScannerTab tab = fixture.connected(inventory(List.of()), this::install);
        InventoryTabs tabs = fromEdt(() -> find(tab, InventoryTabs.class));

        assertThat(titles(tabs)).last().isEqualTo("Access");

        matrix.record(toolKey("delete"), BOB.id(), AccessOutcome.SAME_RESULT);
        matrix.recordFinding(toolKey("delete"), BOB.id(),
                new AccessFinding(AccessFinding.Kind.OBJECT_LEVEL, "Object-level: bob"));
        flushEdt();
        flushEdt();
        assertThat(titles(tabs)).last().isEqualTo("Access (1 issue)");
    }

    @Test
    void writeToolsConfirmedForAScanMayBeReplayedAsOtherIdentities() throws Exception {
        fixture.scanPrompt = (parent, tools, count, invoker) -> new DestructiveScanConfirmation.Result(true, false);
        McpScannerTab tab = fixture.connected(inventory(List.of(destructiveTool("destroy"))), this::install);

        onEdt(() -> {
            tools(tab).getTableModel().setValueAt(true, 0, 0);
            click(scanButton(tab));
        });

        await().atMost(ofSeconds(5)).untilAsserted(() -> verify(fixture.scanLauncher)
                .launchScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), anyMap()));
        assertThat(confirmations.confirmed("destroy")).isTrue();
    }

    @Test
    void checkAccessConfirmsWriteToolsAsAReplayNotAsAScan() throws Exception {
        List<DestructiveScanConfirmation.Lines> asked = new java.util.concurrent.CopyOnWriteArrayList<>();
        fixture.minedWritePrompt = (parent, lines) -> {
            asked.add(lines);
            return new DestructiveScanConfirmation.Result(false, false);
        };
        McpScannerTab tab = fixture.connected(inventory(List.of()), this::install);
        AccessPanel access = fromEdt(() -> find(tab, AccessPanel.class));

        onEdt(() -> SwingTree.button(access, "Check access").doClick());

        assertThat(asked).singleElement().satisfies(lines -> {
            assertThat(lines.purpose()).isEqualTo(DestructiveScanConfirmation.Purpose.CHECK_ACCESS);
            assertThat(lines.lead()).doesNotContain("attacker-controlled");
        });
    }

    @Test
    void emptyStateAddsAStarterIdentityThroughTheIdentitiesSectionAndOpensIt() throws Exception {
        McpScannerTab tab = fixture.connected(inventory(List.of()), this::install);
        AccessPanel access = fromEdt(() -> find(tab, AccessPanel.class));

        onEdt(() -> SwingTree.button(access, "Add lower-privilege user\u2026").doClick());

        assertThat(fixture.identities.otherUsers()).singleElement()
                .satisfies(identity -> assertThat(identity.role()).isEqualTo(IdentityRole.LOWER));
        assertThat(fromEdt(() -> drawer(tab).expandedSection())).contains(McpScannerTab.USERS_SECTION);
    }

    @Test
    void emptyStateOpensTheIdentitiesSection() throws Exception {
        McpScannerTab tab = fixture.connected(inventory(List.of()), this::install);
        AccessPanel access = fromEdt(() -> find(tab, AccessPanel.class));
        onEdt(() -> drawer(tab).collapse());

        onEdt(() -> SwingTree.descendants(access).stream().filter(HyperlinkLabel.class::isInstance)
                .map(HyperlinkLabel.class::cast).filter(link -> "Open Users".equals(link.getText()))
                .findFirst().orElseThrow().activate());

        assertThat(fromEdt(() -> drawer(tab).expandedSection())).contains(McpScannerTab.USERS_SECTION);
    }

    private void install(McpScannerTab tab) {
        OwnerRequests requests = new OwnerRequests(target -> { throw new IllegalStateException("unused"); },
                new IdentityRequests(identities::roster));
        CheckAccessRunner runner = new CheckAccessRunner(new RecordingComparison(), new RecordingHttp(), requests,
                issue -> { }, new WriteReplays(confirmations, new MatrixAccessLedger(matrix, confirmations)), runs,
                McpEventLog.noop());
        tab.installAccess(new AccessServices(matrix, runner, requests, confirmations, () -> { }, fixture.identities::otherUserCount));
    }

    private static List<String> titles(InventoryTabs tabs) throws Exception {
        return fromEdt(() -> IntStream.range(0, tabs.getTabCount()).mapToObj(tabs::getTitleAt).toList());
    }
}
