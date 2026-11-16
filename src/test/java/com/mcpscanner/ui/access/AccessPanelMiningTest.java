package com.mcpscanner.ui.access;

import com.mcpscanner.access.AccessFixtures;
import com.mcpscanner.access.mining.MiningCall;
import com.mcpscanner.access.mining.MiningPreferences;
import com.mcpscanner.access.mining.MiningReport;
import com.mcpscanner.access.mining.MiningStop;
import com.mcpscanner.access.mining.MiningReply;
import com.mcpscanner.access.mining.WriteToolOptIn;
import com.mcpscanner.identity.EnteredValue;
import com.mcpscanner.identity.MinedSource;
import com.mcpscanner.identity.MinedValue;
import com.mcpscanner.identity.MinedValueOriginGuard;
import com.mcpscanner.identity.ValueScope;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JTable;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static com.mcpscanner.access.AccessFixtures.ALICE;
import static com.mcpscanner.access.AccessFixtures.BOB;
import static com.mcpscanner.access.AccessFixtures.readOnlyTool;
import static com.mcpscanner.access.AccessFixtures.tool;
import static com.mcpscanner.ui.access.AccessPanelFixture.onEdt;
import static com.mcpscanner.ui.access.AccessPanelFixture.run;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class AccessPanelMiningTest {

    private static final MinedSource SOURCE = new MinedSource("tools/call list_documents", "documents[0].doc_id");

    private AccessPanelFixture access;
    private MiningUiFixture mining;
    private final List<List<MiningCall.ToolCall>> writeApprovals = new CopyOnWriteArrayList<>();
    private AccessPanel panel;

    @BeforeEach
    void setUp() throws Exception {
        MontoyaTestFactory.install();
        access = new AccessPanelFixture(new AccessFixtures().compare(BOB)
                .lists(ALICE, List.of(readOnlyTool("search"), tool("delete_project")), List.of())
                .lists(BOB, List.of(readOnlyTool("search")), List.of()));
        mining = new MiningUiFixture();
        panel = onEdt(() -> new AccessPanel(access.services().withMining(mining.services()),
                new AccessApprovals(tools -> true, (user, calls) -> writeApprovals.add(calls)), access::repeater,
                message -> { }));
    }

    @AfterEach
    void tearDown() {
        mining.close();
        access.close();
    }

    @Test
    void mineIdsMinesEveryUserAndListsWhatItFoundWithItsSource() throws Exception {
        run(() -> control().mineButton().doClick());

        awaitFinished();
        assertThat(onEdt(() -> control().progress().getText())).isEqualTo("Collected 2 private and 0 shared IDs");
        assertThat(rows()).contains(List.of("d-alice-0001", "doc_id",
                "tools/call list_documents · structuredContent.documents[0].doc_id", "Private", "Collected"));
        run(() -> values().userCombo().setSelectedIndex(1));
        assertThat(rows()).extracting(row -> row.get(0)).containsExactly("d-bob-0042");
    }

    @Test
    void clearingOneUsersMinedValuesResetsTheMiningSummary() throws Exception {
        run(() -> control().mineButton().doClick());
        awaitFinished();

        mining.dialogs.clearAnswers.add(ClearChoice.THIS_USER);
        run(() -> values().clearButton().doClick());

        await().until(() -> onEdt(() -> control().progress().getText()).isEmpty());
        assertThat(onEdt(() -> control().lastReport())).isEmpty();
    }

    @Test
    void anEndpointOriginChangeThatClearsMinedValuesResetsTheMiningSummary() throws Exception {
        MinedValueOriginGuard guard = MinedValueOriginGuard.watching(mining.registry, McpEventLog.noop(),
                () -> "http://127.0.0.1:8740/mcp");
        run(() -> control().mineButton().doClick());
        awaitFinished();

        guard.commit("http://127.0.0.1:9999/mcp");

        await().until(() -> onEdt(() -> control().progress().getText()).isEmpty());
    }

    @Test
    void enteringAValueKeepsTheMiningSummary() throws Exception {
        run(() -> control().mineButton().doClick());
        awaitFinished();

        mining.store.replaceEntered(mining.alice.id(), List.of(new EnteredValue("doc_id", "typed")));

        assertThat(onEdt(() -> control().progress().getText())).isEqualTo("Collected 2 private and 0 shared IDs");
    }

    @Test
    void mineIdsAsksOncePerConnectionBeforeCallingAWriteTool() throws Exception {
        optInArchive();
        mining.dialogs.confirmAnswers.add(false);
        run(() -> control().mineButton().doClick());
        assertThat(mining.mining.running()).isFalse();
        assertThat(mining.store.valuesOf(mining.alice.id()).mined()).isEmpty();

        run(() -> control().mineButton().doClick());
        awaitFinished();
        run(() -> control().mineButton().doClick());
        awaitFinished();
        assertThat(mining.dialogs.asked).containsExactly("confirm-mining", "confirm-mining");

        run(mining.mining::reset);
        run(() -> control().mineButton().doClick());
        awaitFinished();
        assertThat(mining.dialogs.asked).containsExactly("confirm-mining", "confirm-mining", "confirm-mining");
    }

    @Test
    void theMineIdsConfirmationListsTheToolsMiningWillCall() throws Exception {
        optInArchive();
        mining.dialogs.confirmAnswers.add(false);

        run(() -> control().mineButton().doClick());

        assertThat(mining.dialogs.confirmedTools).extracting(ToolsToCall::names)
                .containsExactly(List.of("list_documents", "get_document", "archive_document"));
    }

    @Test
    void mineIdsWithOnlyReadOnlyToolsStartsWithoutAsking() throws Exception {
        run(() -> control().mineButton().doClick());

        awaitFinished();
        assertThat(mining.dialogs.asked).isEmpty();
    }

    @Test
    void choosingMineAtTheMineFirstPromptCountsAsTheConfirmation() throws Exception {
        optInArchive();
        mining.dialogs.mineFirstAnswers.add(MineFirstChoice.MINE);
        run(() -> checkButton().doClick());
        await().atMost(10, TimeUnit.SECONDS).until(() -> !access.check.compared().isEmpty());
        await().until(() -> onEdt(() -> checkButton().getText()).startsWith("Check access"));

        run(() -> control().mineButton().doClick());
        awaitFinished();

        assertThat(mining.dialogs.asked).containsExactly("mine-first");
    }

    @Test
    void cancelStopsMiningAndSavesNothing() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        mining.sender.set((identity, call) -> {
            awaitQuietly(release);
            return MiningUiFixture.documents(identity, call);
        });

        run(() -> control().mineButton().doClick());
        assertThat(onEdt(() -> control().cancelButton().isEnabled())).isTrue();
        assertThat(onEdt(() -> control().mineButton().isEnabled())).isFalse();
        run(() -> control().cancelButton().doClick());
        release.countDown();

        awaitFinished();
        assertThat(awaitFinished().stop()).isEqualTo(MiningStop.CANCELLED);
        assertThat(mining.store.valuesOf(mining.alice.id()).mined()).isEmpty();
    }

    @Test
    void warnsWhenAUserFoundNothing() throws Exception {
        mining.sender.set((identity, call) -> identity.name().equals("bob")
                ? MiningReply.of(200, MiningUiFixture.structured("{}")) : MiningUiFixture.documents(identity, call));

        run(() -> control().mineButton().doClick());

        assertThat(awaitFinished().warnings()).anyMatch(line -> line.startsWith("bob: collecting found no IDs"));
        assertThat(onEdt(() -> control().usersWithoutIds())).containsExactly(mining.bob.id());
    }

    @Test
    void addsEditsAndDeletesEnteredValues() throws Exception {
        mining.dialogs.enteredAnswers.add(Optional.of(new EnteredValue("doc_id", "typed-1")));
        run(() -> values().addButton().doClick());
        await().until(() -> rows().size() == 1);

        mining.dialogs.enteredAnswers.add(Optional.of(new EnteredValue("doc_id", "typed-2")));
        run(() -> {
            values().table().setRowSelectionInterval(0, 0);
            values().editButton().doClick();
        });
        await().until(() -> rows().equals(List.of(List.of("typed-2", "doc_id", "—", "—", "Entered"))));

        run(() -> {
            values().table().setRowSelectionInterval(0, 0);
            values().deleteButton().doClick();
        });
        await().until(() -> rows().isEmpty());
        assertThat(mining.store.valuesOf(mining.alice.id()).isEmpty()).isTrue();
    }

    @Test
    void deletesAMinedValueButCannotEditIt() throws Exception {
        mining.store.replaceMined(mining.alice.id(), List.of(mined("d-1"), mined("d-2")));
        await().until(() -> rows().size() == 2);

        run(() -> values().table().setRowSelectionInterval(0, 0));
        assertThat(onEdt(() -> values().editButton().isEnabled())).isFalse();
        run(() -> values().deleteButton().doClick());

        await().until(() -> rows().size() == 1);
        assertThat(mining.store.valuesOf(mining.alice.id()).mined()).containsExactly(mined("d-2"));
    }

    @Test
    void clearsMinedValuesForOneUserOrAllOnlyAfterConfirmation() throws Exception {
        mining.store.replaceMined(mining.alice.id(), List.of(mined("d-1")));
        mining.store.replaceMined(mining.bob.id(), List.of(mined("d-9")));
        mining.store.replaceEntered(mining.alice.id(), List.of(new EnteredValue("doc_id", "typed")));

        run(() -> values().clearButton().doClick());
        assertThat(mining.store.valuesOf(mining.alice.id()).mined()).hasSize(1);

        mining.dialogs.clearAnswers.add(ClearChoice.THIS_USER);
        run(() -> values().clearButton().doClick());
        assertThat(mining.store.valuesOf(mining.alice.id()).mined()).isEmpty();
        assertThat(mining.store.valuesOf(mining.alice.id()).entered()).hasSize(1);
        assertThat(mining.store.valuesOf(mining.bob.id()).mined()).hasSize(1);

        mining.dialogs.clearAnswers.add(ClearChoice.ALL_USERS);
        run(() -> values().clearButton().doClick());
        assertThat(mining.store.valuesOf(mining.bob.id()).mined()).isEmpty();
        assertThat(mining.dialogs.asked).containsExactly("clear alice", "clear alice", "clear alice");
    }

    @Test
    void persistsThePassCount() throws Exception {
        assertThat(onEdt(() -> control().passes().getValue())).isEqualTo(2);

        run(() -> control().passes().setValue(4));

        assertThat(new MiningPreferences(mining.config).passes()).isEqualTo(4);
    }

    @Test
    void minedIdsInWriteToolsIsOffByDefaultAndPersisted() throws Exception {
        assertThat(onEdt(() -> control().minedInWriteTools().isSelected())).isFalse();

        run(() -> control().minedInWriteTools().doClick());

        assertThat(new MiningPreferences(mining.config).minedIdsInWriteTools()).isTrue();
        assertThat(onEdt(() -> control().minedInWriteTools().getText())).isEqualTo("Use collected IDs in write tools");
    }

    @Test
    void writeToolsAreOffByDefaultAndCanBeAllowedAllOrFromAList() throws Exception {
        WriteToolOptInControl writeTools = control().writeTools();
        assertThat(onEdt(() -> writeTools.choice().getSelectedItem())).isEqualTo(WriteToolChoice.READ_ONLY);
        assertThat(onEdt(() -> writeTools.chooseButton().isVisible())).isFalse();

        run(() -> writeTools.choice().setSelectedItem(WriteToolChoice.ALL));
        assertThat(new MiningPreferences(mining.config).writeTools()).isEqualTo(WriteToolOptIn.ALL);

        run(() -> writeTools.choice().setSelectedItem(WriteToolChoice.SELECTED));
        assertThat(onEdt(() -> writeTools.choice().getSelectedItem())).isEqualTo(WriteToolChoice.ALL);

        mining.dialogs.toolAnswers.add(Optional.of(Set.of("archive_document")));
        run(() -> writeTools.choice().setSelectedItem(WriteToolChoice.SELECTED));
        assertThat(new MiningPreferences(mining.config).writeTools())
                .isEqualTo(WriteToolOptIn.selected(Set.of("archive_document")));
        assertThat(mining.dialogs.offeredTools).allSatisfy(tools -> assertThat(tools).containsExactly("archive_document"));
        assertThat(onEdt(() -> writeTools.chooseButton().isVisible())).isTrue();
    }

    @Test
    void anAllowedWriteToolIsConfirmedAgainWhenItWouldReceiveRealIdsNotShownYet() throws Exception {
        mining.mining.preferences().setWriteTools(WriteToolOptIn.selected(Set.of("archive_document")));

        run(() -> control().mineButton().doClick());

        awaitFinished();
        assertThat(writeApprovals).hasSize(3);
        assertThat(writeApprovals.get(0)).allSatisfy(call -> assertThat(call.arguments()).isEmpty());
        assertThat(writeApprovals.subList(1, 3)).extracting(calls -> calls.get(0).arguments().get("doc_id").asText())
                .containsExactlyInAnyOrder("d-alice-0001", "d-bob-0042");
    }

    @Test
    void checkAccessAsksToMineFirstAndCancelRunsNothing() throws Exception {
        run(() -> checkButton().doClick());

        assertThat(mining.dialogs.asked).containsExactly("mine-first");
        assertThat(access.check.compared()).isEmpty();
        assertThat(mining.mining.running()).isFalse();
    }

    @Test
    void continueWithoutRunsTheCheckWithoutMining() throws Exception {
        mining.dialogs.mineFirstAnswers.add(MineFirstChoice.CONTINUE_WITHOUT);

        run(() -> checkButton().doClick());

        await().until(() -> !access.check.compared().isEmpty());
        assertThat(mining.store.valuesOf(mining.alice.id()).mined()).isEmpty();
    }

    @Test
    void mineRunsMiningThenTheOriginalCheckAndDoesNotAskAgain() throws Exception {
        mining.dialogs.mineFirstAnswers.add(MineFirstChoice.MINE);

        run(() -> checkButton().doClick());

        await().atMost(10, TimeUnit.SECONDS).until(() -> !access.check.compared().isEmpty());
        assertThat(mining.store.valuesOf(mining.alice.id()).mined()).isNotEmpty();
        await().until(() -> onEdt(() -> checkButton().getText()).startsWith("Check access"));
        int checked = access.check.compared().size();

        run(() -> checkButton().doClick());

        await().until(() -> access.check.compared().size() > checked);
        assertThat(mining.dialogs.asked).containsExactly("mine-first");
    }

    @Test
    void aRateLimitedMiningRunDoesNotContinueToTheCheck() throws Exception {
        mining.sender.set((identity, call) -> MiningReply.of(429, null));
        mining.dialogs.mineFirstAnswers.add(MineFirstChoice.MINE);

        run(() -> checkButton().doClick());

        awaitFinished();
        assertThat(access.check.compared()).isEmpty();
        assertThat(mining.store.valuesOf(mining.alice.id()).mined()).isEmpty();
        assertThat(mining.mining.minedForCurrentIdentities()).isFalse();
    }

    @Test
    void launchesWaitWhileMiningRunsAndStartOnceItCompletes() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        mining.sender.set((identity, call) -> {
            awaitQuietly(release);
            return MiningUiFixture.documents(identity, call);
        });
        List<String> launched = new CopyOnWriteArrayList<>();
        run(() -> control().mineButton().doClick());

        run(() -> checkButton().doClick());
        run(() -> panel.mineFirst().run(() -> launched.add("scan")));

        assertThat(access.check.compared()).isEmpty();
        assertThat(launched).isEmpty();
        assertThat(mining.dialogs.asked).isEmpty();
        release.countDown();
        await().atMost(10, TimeUnit.SECONDS).until(() -> !access.check.compared().isEmpty());
        assertThat(launched).containsExactly("scan");
    }

    @Test
    void launchesQueuedBehindACancelledRunNeverStart() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        mining.sender.set((identity, call) -> {
            awaitQuietly(release);
            return MiningUiFixture.documents(identity, call);
        });
        List<String> launched = new CopyOnWriteArrayList<>();
        run(() -> control().mineButton().doClick());
        run(() -> panel.mineFirst().run(() -> launched.add("scan")));

        run(() -> control().cancelButton().doClick());
        release.countDown();

        awaitFinished();
        run(() -> { });
        assertThat(launched).isEmpty();
    }

    @Test
    void theScanGateAsksTheSameQuestion() throws Exception {
        mining.dialogs.mineFirstAnswers.add(MineFirstChoice.CONTINUE_WITHOUT);
        List<String> launched = new CopyOnWriteArrayList<>();

        run(() -> panel.mineFirst().run(() -> launched.add("scan")));

        assertThat(launched).containsExactly("scan");
        assertThat(mining.dialogs.asked).containsExactly("mine-first");
    }

    @Test
    void aDisconnectedPanelNeverAsks() throws Exception {
        mining.inventory.set(Optional.empty());
        List<String> launched = new CopyOnWriteArrayList<>();

        run(() -> panel.mineFirst().run(() -> launched.add("scan")));

        assertThat(launched).containsExactly("scan");
        assertThat(mining.dialogs.asked).isEmpty();
    }

    private void optInArchive() {
        mining.mining.preferences().setWriteTools(WriteToolOptIn.selected(Set.of("archive_document")));
    }

    private MiningReport awaitFinished() throws Exception {
        await().atMost(10, TimeUnit.SECONDS).until(() -> !mining.mining.running()
                && onEdt(() -> control().lastReport()).isPresent());
        return onEdt(() -> control().lastReport()).orElseThrow();
    }

    private MineIdsControl control() {
        return panel.mining().orElseThrow().control();
    }

    private OwnedValuesView values() {
        return panel.mining().orElseThrow().values();
    }

    private javax.swing.JButton checkButton() {
        return panel.matrixView().toolbar().checkButton();
    }

    private List<List<String>> rows() throws Exception {
        return onEdt(() -> {
            JTable table = values().table();
            List<List<String>> rows = new java.util.ArrayList<>();
            for (int row = 0; row < table.getRowCount(); row++) {
                List<String> cells = new java.util.ArrayList<>();
                for (int column = 0; column < table.getColumnCount(); column++) {
                    cells.add(String.valueOf(table.getValueAt(row, column)));
                }
                rows.add(cells);
            }
            return rows;
        });
    }

    private static MinedValue mined(String value) {
        return new MinedValue("doc_id", value, SOURCE, ValueScope.PRIVATE);
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
