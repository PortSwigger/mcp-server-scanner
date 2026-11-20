package com.mcpscanner.ui;

import com.mcpscanner.access.AccessFixtures;
import com.mcpscanner.access.AccessMatrix;
import com.mcpscanner.access.AccessRuns;
import com.mcpscanner.access.CheckAccessRunner;
import com.mcpscanner.access.IdentityRequests;
import com.mcpscanner.access.MatrixAccessLedger;
import com.mcpscanner.access.OwnerRequests;
import com.mcpscanner.access.RecordingComparison;
import com.mcpscanner.access.RecordingHttp;
import com.mcpscanner.access.WriteReplayConfirmations;
import com.mcpscanner.access.WriteReplays;
import com.mcpscanner.access.mining.AccessMining;
import com.mcpscanner.access.mining.MiningPreferences;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.RegistryOwnedValues;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.SwingTree;
import com.mcpscanner.ui.access.AccessPanel;
import com.mcpscanner.ui.access.AccessServices;
import com.mcpscanner.ui.access.MiningDialogs;
import com.mcpscanner.ui.access.MiningServices;
import com.mcpscanner.ui.completion.ValueCompletion;
import com.mcpscanner.ui.identities.PrimaryUserPicker;
import com.mcpscanner.ui.identities.ScanAsChip;
import com.mcpscanner.ui.identities.UsersPanel;
import com.mcpscanner.ui.scans.MessageEditors;
import com.mcpscanner.ui.scans.ScanControls;
import com.mcpscanner.ui.scans.ScanFeed;
import com.mcpscanner.ui.scans.ScansPanel;
import com.mcpscanner.ui.scans.ScansServices;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.awt.Component;
import java.util.List;
import java.util.concurrent.Executors;

import static com.mcpscanner.ui.EditionTabProbe.everyComponentInEverySection;
import static com.mcpscanner.ui.EditionTabProbe.isLabelled;
import static com.mcpscanner.ui.EditionTabProbe.oneItemOfEachKind;
import static com.mcpscanner.ui.EditionTabProbe.promptArgumentMenuLabel;
import static com.mcpscanner.ui.EditionTabProbe.texts;
import static com.mcpscanner.ui.EditionTabProbe.tickBoxColumnsOf;
import static com.mcpscanner.ui.EditionTabProbe.tickableInventoryPanels;
import static com.mcpscanner.ui.EditionTabProbe.toolRowMenuTexts;
import static com.mcpscanner.ui.McpScannerTabFixture.drawer;
import static com.mcpscanner.ui.McpScannerTabFixture.find;
import static com.mcpscanner.ui.McpScannerTabFixture.fromEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.onEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.scanBar;
import static com.mcpscanner.ui.McpScannerTabFixture.tools;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Tag(EditionTabProbe.EDITION_UI)
class McpScannerTabProfessionalTest {

    private static final List<Class<?>> PROFESSIONAL_PARTS = List.of(ScanBar.class, ScanChecksPanel.class,
            RequestFamiliesPanel.class, AccessPanel.class, ScansPanel.class, ScanAsChip.class,
            PrimaryUserPicker.class, SignedInConsentOption.class);
    private static final List<String> PROFESSIONAL_TEXTS = List.of("Scan", "Select read-only", "Collect IDs",
            "Add peer", "Add lower-privilege user", "Scan as", "Refresh as all users", "Add user", "Sign in all",
            "Compared users", "Scan warnings", "Extension scan workers",
            SignedInConsentOption.LABEL);
    private static final List<String> CROSS_IDENTITY_TEXTS = List.of("Private marker",
            "Finding it in another user's reply", "Compared user: bob", "do not compare users");

    private final McpScannerTabFixture fixture = new McpScannerTabFixture();
    private final AccessRuns runs = new AccessRuns(Executors.newSingleThreadExecutor());
    private McpScannerTab tab;

    @BeforeEach
    void connectInProfessional() throws Exception {
        fixture.professional = true;
        tab = fixture.connected(oneItemOfEachKind(), this::installProfessionalPanels);
    }

    @AfterEach
    void stopAccessRuns() {
        runs.shutdown();
    }

    @Test
    void buildsEveryScanCheckAccessAndScansPart() throws Exception {
        List<Component> everything = everyComponentInEverySection(tab);

        assertThat(PROFESSIONAL_PARTS).allSatisfy(part -> assertThat(everything).anyMatch(part::isInstance));
    }

    @Test
    void theScanBarShowsScanItsModeAndAChecksSummary() throws Exception {
        ScanBar bar = fromEdt(() -> scanBar(tab));
        List<Component> barParts = fromEdt(() -> SwingTree.descendants(bar));

        assertThat(barParts).contains(bar.scanButton(), bar.checksSummary());
        assertThat(bar.scanButton().getText()).matches("Scan( \\d+ .+)?");
        assertThat(texts(barParts)).anyMatch(text -> text.startsWith("Mode: "));
        assertThat(bar.checksSummary().getText()).contains("checks on");
    }

    @Test
    void offersTheChecksAndRequestsSections() throws Exception {
        assertThat(fromEdt(() -> drawer(tab).sectionOrder()))
                .contains(McpScannerTab.CHECKS_SECTION, McpScannerTab.REQUESTS_SECTION);
    }

    @Test
    void showsEveryScanCompareAndCollectIdsControl() throws Exception {
        List<String> texts = texts(everyComponentInEverySection(tab));

        assertThat(PROFESSIONAL_TEXTS).allSatisfy(professional ->
                assertThat(texts).anyMatch(text -> isLabelled(text, professional)));
    }

    @Test
    void theAccessPanelOffersCollectIds() throws Exception {
        List<String> accessTexts = fromEdt(() -> texts(SwingTree.descendants(find(tab, AccessPanel.class))));

        assertThat(accessTexts).anyMatch(text -> isLabelled(text, "Collect IDs"));
    }

    @Test
    void aComparedUserCanBeMadeThePrimaryUserAndCarriesCrossIdentityControls() throws Exception {
        Identity bob = fixture.identities.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        onEdt(() -> find(tab, UsersPanel.class).select(bob.id()));

        List<String> texts = texts(everyComponentInEverySection(tab));

        assertThat(texts).anyMatch(text -> isLabelled(text, "Make primary user"));
        assertThat(CROSS_IDENTITY_TEXTS).allSatisfy(crossIdentity ->
                assertThat(texts).anyMatch(text -> text.contains(crossIdentity)));
    }

    @Test
    void aMalformedItemIsDescribedInScanTerms() throws Exception {
        String problems = fromEdt(() -> {
            tools(tab).populate(List.of(new McpToolDefinition(null, null, null)));
            tools(tab).table().setRowSelectionInterval(0, 0);
            return tools(tab).detailPanel().problemsLine().getText();
        });

        assertThat(problems).startsWith("Malformed: ").endsWith(" It cannot be scanned.");
    }

    @Test
    void inventoryDetailsExplainTheScanArguments() throws Exception {
        List<String> texts = texts(everyComponentInEverySection(tab));

        assertThat(texts).anyMatch(text -> text.startsWith("Scans call this tool with default arguments"));
        assertThat(texts).anyMatch(text -> text.startsWith("Scans fill each argument with a default string"));
    }

    @Test
    void everyInventoryTabOffersScanThisItemOnTheSelectedRow() throws Exception {
        assertThat(texts(everyComponentInEverySection(tab))).contains("Scan this tool", "Scan this resource",
                "Scan this template", "Scan this prompt");
    }

    @Test
    void keepsThePrimaryUserForSignIn() throws Exception {
        assertThat(texts(everyComponentInEverySection(tab))).contains("Primary user");
    }

    @Test
    void showsNoProfessionalNoteInPlaceOfTheScanBar() throws Exception {
        List<Component> everything = everyComponentInEverySection(tab);

        assertThat(texts(everything)).doesNotContain(ScanUnavailable.NOTE);
        assertThat(everything).noneMatch(ScanUnavailable.class::isInstance);
    }

    @Test
    void theUsersLabelCountsComparedUsers() throws Exception {
        fixture.identities.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        fixture.identities.add(Identity.create("carol", IdentityRole.LOWER, IdentityAuthKind.BEARER));
        onEdt(() -> { });

        assertThat(fromEdt(() -> drawer(tab).labelOf(McpScannerTab.USERS_SECTION))).isEqualTo("Users (3)");
    }

    @Test
    void offersAWriteReplayApproval() {
        assertThat(tab.writeReplayApproval()).isPresent();
    }

    @Test
    void opensTheChecksSectionByDefault() throws Exception {
        McpScannerTab fresh = fromEdt(fixture::newTab);

        assertThat(fromEdt(() -> drawer(fresh).expandedSection())).contains(McpScannerTab.CHECKS_SECTION);
    }

    @Test
    void inventoryTablesHaveATickBoxColumn() throws Exception {
        onEdt(() -> tickableInventoryPanels(tab).forEach(panel ->
                assertThat(tickBoxColumnsOf(panel)).isNotEmpty()));
    }

    @Test
    void sendsToRepeaterAndOrganizer() throws Exception {
        assertThat(toolRowMenuTexts(tab)).contains("Send to Repeater", "Send to Organizer");
    }

    @Test
    void asksTheServerForValues() throws Exception {
        assertThat(promptArgumentMenuLabel(tab)).contains(ValueCompletion.MENU_LABEL);
    }

    private void installProfessionalPanels(McpScannerTab professionalTab) {
        professionalTab.installAccess(accessServices());
        professionalTab.installScans(new ScansServices(mock(ScanFeed.class), mock(ScanControls.class),
                location -> { }, mock(MessageEditors.class)));
    }

    private AccessServices accessServices() {
        AccessFixtures access = new AccessFixtures();
        AccessMatrix matrix = access.matrix();
        WriteReplayConfirmations confirmations = new WriteReplayConfirmations();
        OwnerRequests requests = new OwnerRequests(target -> { throw new IllegalStateException("unused"); },
                new IdentityRequests(access::roster));
        CheckAccessRunner runner = new CheckAccessRunner(new RecordingComparison(), new RecordingHttp(), requests,
                issue -> { }, new WriteReplays(confirmations, new MatrixAccessLedger(matrix, confirmations)),
                runs, McpEventLog.noop());
        return new AccessServices(matrix, runner, requests, confirmations, () -> { },
                fixture.identities::otherUserCount)
                .withMining(new MiningServices(idleMining(), new RegistryOwnedValues(fixture.identities),
                        fixture.identities::identities, mock(MiningDialogs.class)));
    }

    private static AccessMining idleMining() {
        MiningPreferences preferences = new MiningPreferences(InMemoryPersistedObject.configStore());
        AccessMining mining = mock(AccessMining.class);
        when(mining.preferences()).thenReturn(preferences);
        return mining;
    }
}
