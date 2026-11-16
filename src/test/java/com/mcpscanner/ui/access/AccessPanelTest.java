package com.mcpscanner.ui.access;

import com.mcpscanner.access.AccessFixtures;
import com.mcpscanner.access.AccessFilter;
import com.mcpscanner.access.AccessRow;
import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessFinding;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.mcp.ScannerSentinels;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.ui.widgets.Contrast;
import com.mcpscanner.ui.widgets.ThemeColors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JTable;
import java.awt.Color;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import static com.mcpscanner.access.AccessFixtures.ALICE;
import static com.mcpscanner.access.AccessFixtures.BOB;
import static com.mcpscanner.access.AccessFixtures.CAROL;
import static com.mcpscanner.access.AccessFixtures.readOnlyTool;
import static com.mcpscanner.access.AccessFixtures.resource;
import static com.mcpscanner.access.AccessFixtures.tool;
import static com.mcpscanner.access.AccessFixtures.toolKey;
import static com.mcpscanner.ui.access.AccessPanelFixture.onEdt;
import static com.mcpscanner.ui.access.AccessPanelFixture.run;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class AccessPanelTest {

    private AccessPanelFixture fixture;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        fixture = new AccessPanelFixture(new AccessFixtures().compare(BOB, CAROL)
                .lists(ALICE, List.of(readOnlyTool("search"), tool("delete_project"), readOnlyTool("list_users")),
                        List.of(resource("notes://alice/private.md")))
                .lists(BOB, List.of(readOnlyTool("search"), tool("delete_project")), List.of())
                .lists(CAROL, List.of(readOnlyTool("search")), List.of()));
    }

    @AfterEach
    void tearDown() {
        fixture.close();
    }

    @Test
    void withoutAnyOtherIdentityTheEmptyStateOffersToAddOne() throws Exception {
        AccessPanel panel = fixture.otherUserCount(0).panel();
        AccessEmptyState empty = panel.emptyState();
        AtomicInteger peers = new AtomicInteger();
        AtomicInteger lowers = new AtomicInteger();
        AtomicInteger opened = new AtomicInteger();

        assertThat(panel.visibleCard()).isEqualTo(AccessPanel.EMPTY_CARD);
        assertThat(AccessEmptyState.BODY).contains("Only the primary user exists so far");
        assertThat(empty.addPeerButton().isEnabled()).isFalse();
        run(() -> panel.setIdentityShortcuts(new IdentityShortcuts() {
            public void addPeer() { peers.incrementAndGet(); }
            public void addLowerPrivilegeUser() { lowers.incrementAndGet(); }
            public void openIdentities() { opened.incrementAndGet(); }
        }));
        run(() -> {
            empty.addPeerButton().doClick();
            empty.addLowerButton().doClick();
            empty.openIdentitiesLink().activate();
        });

        assertThat(List.of(peers.get(), lowers.get(), opened.get())).containsExactly(1, 1, 1);
        assertThat(empty.addPeerButton().getText()).isEqualTo("Add peer…");
    }

    @Test
    void withOnlyThePrimaryUserThePanelShowsTheEmptyCard() throws Exception {
        assertThat(fixture.otherUserCount(0).panel().visibleCard()).isEqualTo(AccessPanel.EMPTY_CARD);
    }

    @Test
    void withAnotherUserThePanelShowsTheMatrixCard() throws Exception {
        assertThat(fixture.otherUserCount(1).panel().visibleCard()).isEqualTo(AccessPanel.MATRIX_CARD);
    }

    @Test
    void theEmptyCardGivesWayToTheMatrixOnceAnotherUserIsAdded() throws Exception {
        AccessPanel panel = fixture.otherUserCount(0).panel();

        fixture.otherUserCount(1);
        run(panel::refresh);

        assertThat(panel.visibleCard()).isEqualTo(AccessPanel.MATRIX_CARD);
    }

    @Test
    void beforeAnyCheckTheMatrixShowsListingsInferredExpectationsAndTheListingNote() throws Exception {
        AccessMatrixView view = fixture.panel().matrixView();
        JTable table = view.table();

        assertThat(fixture.panel().visibleCard()).isEqualTo(AccessPanel.MATRIX_CARD);
        assertThat(columnNames(table)).containsExactly("Item", "Primary (Primary user)", "bob (peer)", "carol (lower)",
                "Anonymous", "Who should reach it");
        assertThat(text(table, row(table, "list_users"), 0)).isEqualTo("tool  list_users");
        assertThat(text(table, row(table, "list_users"), 2)).isEqualTo("○ hidden · not yet checked");
        assertThat(text(table, row(table, "list_users"), 1)).isEqualTo("● listed · owner");
        assertThat(text(table, row(table, "list_users"), 4)).isEqualTo("not yet checked");
        assertThat(text(table, row(table, "list_users"), 5)).isEqualTo("Only Primary (inferred)");
        assertThat(text(table, row(table, "delete_project"), 5)).isEqualTo("Primary's level or above (inferred)");
        assertThat(view.info().isVisible()).isTrue();
        assertThat(view.info().getText()).isEqualTo(AccessInfoNote.LISTING_ONLY);
        assertThat(view.toolbar().filter() == AccessFilter.ALL).isTrue();
        assertThat(checkButtonText()).isEqualTo("Check access");
        assertThat(fixture.panel().title()).isEqualTo("Access");
    }

    @Test
    void checkAccessIsDisabledWithAReasonWhenNotConnected() throws Exception {
        fixture = new AccessPanelFixture(new AccessFixtures().compare(BOB));

        AccessToolbar toolbar = fixture.panel().matrixView().toolbar();
        assertThat(onEdt(() -> checkButton().isEnabled())).isFalse();
        assertThat(onEdt(() -> checkButton().getToolTipText())).isEqualTo("Connect to an MCP server first");
        assertThat(fixture.panel().matrixView().info().getText()).isEqualTo(AccessInfoNote.DISCONNECTED);
        assertThat(toolbar.refreshButton().isEnabled()).isFalse();
    }

    @Test
    void checkAccessShowsItsScopeBesideAShortLabel() throws Exception {
        Principal alice = new Principal(Principal.PRIMARY_ID, "alice", ALICE.role(), ALICE.credentialHeaders(),
                Optional.empty(), java.util.Map.of());
        fixture = new AccessPanelFixture(new AccessFixtures().withPrimary(alice).compare(BOB)
                .lists(alice, List.of(readOnlyTool("search"), readOnlyTool("list_users")), List.of())
                .lists(BOB, List.of(readOnlyTool("search")), List.of()));

        assertThat(checkButtonText()).isEqualTo("Check access");
        assertThat(scopeText()).isEqualTo("2 items · alice vs bob + Anonymous");
        assertThat(onEdt(() -> toolbar().scopeLabel().isVisible())).isTrue();
        assertThat(onEdt(() -> toolbar().scopeLabel().getForeground())).isEqualTo(ThemeColors.muted());
        assertThat(onEdt(() -> toolbar().noComparisonHint().isVisible())).isFalse();
    }

    @Test
    void withNobodyComparedCheckAccessIsDisabledAndTheHintLinksToIdentities() throws Exception {
        fixture = new AccessPanelFixture(new AccessFixtures().lists(ALICE, List.of(readOnlyTool("search")), List.of()));
        AtomicInteger opened = new AtomicInteger();
        run(() -> fixture.panel().setIdentityShortcuts(new IdentityShortcuts() {
            public void addPeer() { }
            public void addLowerPrivilegeUser() { }
            public void openIdentities() { opened.incrementAndGet(); }
        }));

        assertThat(onEdt(() -> checkButton().isEnabled())).isFalse();
        assertThat(onEdt(() -> checkButton().getToolTipText())).isEqualTo(CheckAccessReadiness.NO_COMPARISON);
        assertThat(CheckAccessReadiness.NO_COMPARISON)
                .isEqualTo("Tick Compare on another user in Users to check access");
        NoComparisonHint hint = toolbar().noComparisonHint();
        assertThat(onEdt(hint::isVisible)).isTrue();
        assertThat(onEdt(hint::text)).isEqualTo(CheckAccessReadiness.NO_COMPARISON);
        assertThat(onEdt(() -> toolbar().scopeLabel().isVisible())).isFalse();
        run(() -> hint.identitiesLink().activate());
        assertThat(opened).hasValue(1);
    }

    @Test
    void withNobodyComparedStartingACheckRunsNothing() throws Exception {
        fixture = new AccessPanelFixture(new AccessFixtures().lists(ALICE, List.of(readOnlyTool("search")), List.of()));
        AccessPanel panel = fixture.panel();
        CheckAccessControl control = controlFor();
        run(() -> control.show(fixture.matrix.snapshot(), fixture.matrix.snapshot().rows()));

        run(() -> control.start(fixture.matrix.snapshot().rows()));

        assertThat(control.running()).isFalse();
        assertThat(control.blocker()).contains(CheckAccessReadiness.NO_COMPARISON);
        assertThat(fixture.check.compared()).isEmpty();
        assertThat(panel.title()).isEqualTo("Access");
    }

    @Test
    void outcomeBreakingTheExpectationIsFlaggedAndItsIssueCountedInTheTitle() throws Exception {
        AccessPanel panel = fixture.panel();
        AtomicInteger titleChanges = new AtomicInteger();
        run(() -> panel.onTitleChange(titleChanges::incrementAndGet));

        fixture.matrix.record(toolKey("delete_project"), CAROL.id(), AccessOutcome.SAME_RESULT);
        fixture.matrix.recordAnonymous(toolKey("delete_project"), AccessOutcome.REFUSED);
        fixture.matrix.recordFinding(toolKey("delete_project"), CAROL.id(), new AccessFinding(AccessFinding.Kind.OPERATION_LEVEL, "Operation-level: test"));
        run(() -> { });

        JTable table = panel.matrixView().table();
        assertThat(text(table, row(table, "delete_project"), 3))
                .isEqualTo("⚠ ○ hidden · ✓ same result · ⚑ issue");
        assertThat(text(table, row(table, "delete_project"), 4)).isEqualTo("✗ refused");
        assertThat(panel.title()).isEqualTo("Access (1 issue)");
        assertThat(titleChanges).hasValue(1);
        assertThat(panel.matrixView().info().getText()).contains("1 of 4 items replayed so far");
        Component anomaly = onEdt(() -> rendered(table, row(table, "delete_project"), 3));
        assertThat(anomaly.getBackground()).isNotEqualTo(table.getBackground());
        assertThat(Contrast.ratio(anomaly.getForeground(), anomaly.getBackground())).isGreaterThanOrEqualTo(4.5);
    }

    @Test
    void outcomesRecordedDuringAnEditKeepTheEditorOpenAndShowOnceItCloses() throws Exception {
        JTable table = fixture.panel().matrixView().table();
        int row = row(table, "list_users");
        run(() -> table.editCellAt(row, 5));

        fixture.matrix.record(toolKey("list_users"), BOB.id(), AccessOutcome.REFUSED);
        run(() -> { });
        run(() -> { });

        assertThat(onEdt(table::isEditing)).isTrue();
        run(() -> table.getCellEditor().cancelCellEditing());
        run(() -> { });
        assertThat(text(table, row(table, "list_users"), 2)).isEqualTo("\u25CB hidden \u00B7 \u2717 refused");
    }

    @Test
    void manyOutcomesInOneTurnRefreshThePanelOnce() throws Exception {
        fixture.panel();
        int before = fixture.panelRefreshes.get();

        run(() -> IntStream.range(0, 20).forEach(index ->
                fixture.matrix.record(toolKey("search"), BOB.id(), AccessOutcome.SAME_RESULT)));
        run(() -> { });

        assertThat(fixture.panelRefreshes.get() - before).isEqualTo(1);
    }

    @Test
    void anomalyColoursStayReadableOnLightAndDarkTables() {
        for (Color base : List.of(Color.WHITE, new Color(0x2B2B2B), new Color(0x1E1F22))) {
            Color background = AnomalyColors.background(base);
            assertThat(background).isNotEqualTo(base);
            assertThat(Contrast.ratio(AnomalyColors.foreground(background), background)).isGreaterThanOrEqualTo(4.5);
        }
    }

    @Test
    void differencesOnlyHidesRowsWhereEveryIdentityMatches() throws Exception {
        AccessMatrixView view = fixture.panel().matrixView();
        fixture.matrix.record(toolKey("search"), BOB.id(), AccessOutcome.SAME_RESULT);
        fixture.matrix.record(toolKey("search"), CAROL.id(), AccessOutcome.SAME_RESULT);

        run(() -> view.toolbar().filterCombo().setSelectedItem(AccessFilter.DIFFERENCES_ONLY));

        assertThat(itemNames(view.table())).doesNotContain("search").contains("list_users", "delete_project");
        assertThat(scopeText()).isEqualTo("4 items · Primary vs bob, carol + Anonymous");
    }

    @Test
    void aLowerUserSameResultUnderAnInferredExpectationOpensTheExpectationPicker() throws Exception {
        AccessMatrixView view = fixture.panel().matrixView();
        JTable table = view.table();
        fixture.matrix.record(toolKey("search"), BOB.id(), AccessOutcome.SAME_RESULT);
        fixture.matrix.record(toolKey("search"), CAROL.id(), AccessOutcome.SAME_RESULT);
        run(() -> fixture.panel().refresh());
        int search = row(table, "search");

        assertThat(text(table, search, 3)).contains("? same result as Primary — allowed? Set Who should reach it");
        assertThat(onEdt(() -> view.openExpectationFrom(search, 2))).isFalse();
        assertThat(onEdt(() -> view.openExpectationFrom(search, 3))).isTrue();
        assertThat(onEdt(table::getEditingColumn)).isEqualTo(5);
        assertThat(onEdt(table::getEditingRow)).isEqualTo(search);
    }

    @Test
    void editingWhoShouldReachItPersistsAndDropsTheInferredSuffix() throws Exception {
        JTable table = fixture.panel().matrixView().table();

        run(() -> table.setValueAt(AccessExpectation.SHARED_BY_DESIGN, row(table, "list_users"), 5));

        assertThat(fixture.fixtures.expectations().stored(toolKey("list_users")))
                .contains(AccessExpectation.SHARED_BY_DESIGN);
        assertThat(text(table, row(table, "list_users"), 5)).isEqualTo("Anyone — same result for everyone");
    }

    @Test
    void checkAccessReplaysEveryVisibleRowAndConfirmsWriteToolsOnce() throws Exception {
        fixture.panel();

        run(() -> checkButton().doClick());

        await().until(() -> fixture.check.compared().size() == 4);
        assertThat(fixture.approvals).singleElement()
                .satisfies(tools -> assertThat(tools).extracting(tool -> tool.name()).containsExactly("delete_project"));
        await().until(() -> onEdt(this::checkButtonText).startsWith("Check access"));
    }

    @Test
    void checkAccessCoversItemsTheDifferencesFilterHides() throws Exception {
        AccessMatrixView view = fixture.panel().matrixView();
        run(() -> view.toolbar().filterCombo().setSelectedItem(AccessFilter.DIFFERENCES_ONLY));
        assertThat(itemNames(view.table())).doesNotContain("search");

        run(() -> checkButton().doClick());

        await().until(() -> fixture.check.compared().size() == 4);
    }

    @Test
    void selectingACellExplainsWhatHappenedAndWhy() throws Exception {
        fixture.panel();
        fixture.matrix.record(toolKey("delete_project"), CAROL.id(), AccessOutcome.SAME_RESULT);
        AccessMatrixView view = fixture.panel().matrixView();
        JTable table = view.table();

        run(() -> table.changeSelection(row(table, "delete_project"), 3, false, false));

        assertThat(view.detail().area().getText()).contains("delete_project — carol (Lower privilege)")
                .contains("Not in carol's own tools/list.")
                .contains("returned the same result as Primary")
                .contains("Primary's level or above").contains("Breaks the expectation");
    }

    @Test
    void aBreakWithoutAnIssueIsHighlightedButNotCountedOrSentToTheSiteMap() throws Exception {
        AccessPanel panel = fixture.panel();
        fixture.matrix.record(toolKey("delete_project"), CAROL.id(), AccessOutcome.SAME_RESULT);
        JTable table = panel.matrixView().table();
        run(() -> { });

        run(() -> table.changeSelection(row(table, "delete_project"), 3, false, false));

        assertThat(panel.title()).isEqualTo("Access");
        assertThat(text(table, row(table, "delete_project"), 3)).startsWith("\u26A0");
        assertThat(panel.matrixView().detail().area().getText()).contains("Breaks the expectation")
                .doesNotContain("site map");
    }

    @Test
    void aCellWithAnIssuePointsToTheSiteMap() throws Exception {
        AccessPanel panel = fixture.panel();
        fixture.matrix.record(toolKey("delete_project"), CAROL.id(), AccessOutcome.SAME_RESULT);
        fixture.matrix.recordFinding(toolKey("delete_project"), CAROL.id(), new AccessFinding(AccessFinding.Kind.OPERATION_LEVEL, "Operation-level: test"));
        JTable table = panel.matrixView().table();
        run(() -> { });

        run(() -> table.changeSelection(row(table, "delete_project"), 3, false, false));

        assertThat(panel.matrixView().detail().area().getText()).contains("site map");
    }

    @Test
    void anonymousReachingTheOwnerResultDoesNotClaimAnIssue() throws Exception {
        AccessPanel panel = fixture.panel();
        fixture.matrix.recordAnonymous(toolKey("search"), AccessOutcome.SAME_RESULT);
        JTable table = panel.matrixView().table();
        run(() -> { });

        run(() -> table.changeSelection(row(table, "search"), 4, false, false));

        assertThat(panel.title()).isEqualTo("Access");
        assertThat(panel.matrixView().detail().area().getText()).contains("Breaks the expectation")
                .doesNotContain("site map");
    }

    @Test
    void refreshAsAllIdentitiesRediscoversListings() throws Exception {
        JButton refresh = fixture.panel().matrixView().toolbar().refreshButton();

        run(refresh::doClick);

        assertThat(fixture.refreshes).hasValue(1);
    }

    @Test
    void rowMenuMarksSharedByDesignSendsThePairToRepeaterAndChecksOneItem() throws Exception {
        AccessRowMenu menu = new AccessRowMenu(fixture.matrix, fixture.requests, fixture::repeater,
                controlFor(), message -> { }, Runnable::run);
        AccessRow listUsers = fixture.matrix.row(toolKey("list_users")).orElseThrow();

        JPopupMenu popup = onEdt(() -> menu.menuFor(fixture.matrix.snapshot(), listUsers, Optional.of(BOB)));
        List<String> labels = items(popup).stream().map(JMenuItem::getText).toList();
        assertThat(labels).containsExactly("Set to “Anyone — same result for everyone”", "Send Primary / bob pair to Repeater",
                "Check this item");

        run(() -> items(popup).get(1).doClick());
        assertThat(fixture.repeaterTitles).containsExactly("list_users as Primary", "list_users as bob");
        assertThat(fixture.repeaterRequests.get(1).headerValue(ScannerSentinels.IDENTITY_HEADER)).isEqualTo("bob");
        assertThat(fixture.repeaterRequests.get(1).headerValue("Authorization")).isEqualTo("Bearer bob-token");

        run(() -> items(popup).get(0).doClick());
        assertThat(fixture.matrix.expectationFor(toolKey("list_users"))).isEqualTo(AccessExpectation.SHARED_BY_DESIGN);

        run(() -> items(popup).get(2).doClick());
        await().until(() -> fixture.check.compared().size() == 1);
    }

    @Test
    void rowMenuOnTheItemColumnOffersAPairForEveryOtherIdentity() throws Exception {
        AccessRowMenu menu = new AccessRowMenu(fixture.matrix, fixture.requests, fixture::repeater, controlFor(),
                message -> { }, Runnable::run);
        AccessRow search = fixture.matrix.row(toolKey("search")).orElseThrow();

        JPopupMenu popup = onEdt(() -> menu.menuFor(fixture.matrix.snapshot(), search, Optional.<Principal>empty()));

        assertThat(items(popup)).extracting(JMenuItem::getText).contains("Send Primary / bob pair to Repeater",
                "Send Primary / carol pair to Repeater");
    }

    private CheckAccessControl controlFor() {
        return new CheckAccessControl(fixture.services().runner(), tools -> true);
    }

    private JButton checkButton() throws Exception {
        return fixture.panel().matrixView().toolbar().checkButton();
    }

    private AccessToolbar toolbar() throws Exception {
        return fixture.panel().matrixView().toolbar();
    }

    private String scopeText() throws Exception {
        return onEdt(() -> toolbar().scopeLabel().getText());
    }

    private String checkButtonText() throws Exception {
        return onEdt(() -> checkButton().getText());
    }

    private static List<JMenuItem> items(JPopupMenu popup) {
        List<JMenuItem> items = new ArrayList<>();
        for (Component component : popup.getComponents()) {
            if (component instanceof JMenuItem item) {
                items.add(item);
            }
        }
        return items;
    }

    private static List<String> columnNames(JTable table) {
        return IntStream.range(0, table.getColumnCount()).mapToObj(table::getColumnName).toList();
    }

    private static List<String> itemNames(JTable table) throws Exception {
        return onEdt(() -> IntStream.range(0, table.getRowCount())
                .mapToObj(index -> ((AccessRow) table.getValueAt(index, 0)).item().key().name()).toList());
    }

    private static int row(JTable table, String name) throws Exception {
        return itemNames(table).indexOf(name);
    }

    private static String text(JTable table, int row, int column) throws Exception {
        return onEdt(() -> ((javax.swing.JLabel) rendered(table, row, column)).getText());
    }

    private static Component rendered(JTable table, int row, int column) {
        return table.prepareRenderer(table.getCellRenderer(row, column), row, column);
    }
}
