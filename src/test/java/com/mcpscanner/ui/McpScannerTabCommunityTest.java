package com.mcpscanner.ui;

import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.testutil.SwingTree;
import com.mcpscanner.ui.access.AccessPanel;
import com.mcpscanner.ui.completion.ValueCompletion;
import com.mcpscanner.ui.identities.PrimaryUserPicker;
import com.mcpscanner.ui.identities.ScanAsChip;
import com.mcpscanner.ui.scans.ScansPanel;
import com.mcpscanner.ui.widgets.HyperlinkLabel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.swing.JLabel;
import java.awt.Component;
import java.util.List;

import static com.mcpscanner.ui.EditionTabProbe.everyComponentInEverySection;
import static com.mcpscanner.ui.EditionTabProbe.isLabelled;
import static com.mcpscanner.ui.EditionTabProbe.oneItemOfEachKind;
import static com.mcpscanner.ui.EditionTabProbe.promptArgumentMenuLabel;
import static com.mcpscanner.ui.EditionTabProbe.texts;
import static com.mcpscanner.ui.EditionTabProbe.tickBoxColumnsOf;
import static com.mcpscanner.ui.EditionTabProbe.tickableInventoryPanels;
import static com.mcpscanner.ui.EditionTabProbe.toolRowMenuTexts;
import static com.mcpscanner.ui.McpScannerTabFixture.drawer;
import static com.mcpscanner.ui.McpScannerTabFixture.fromEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.onEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.tools;
import static org.assertj.core.api.Assertions.assertThat;

@Tag(EditionTabProbe.EDITION_UI)
class McpScannerTabCommunityTest {

    private static final List<Class<?>> PROFESSIONAL_PARTS = List.of(ScanBar.class, ScanChecksPanel.class,
            RequestFamiliesPanel.class, AccessPanel.class, ScansPanel.class, ScanAsChip.class,
            PrimaryUserPicker.class, SignedInConsentOption.class);
    private static final List<String> PROFESSIONAL_TEXTS = List.of("Scan", "Select read-only", "Collect IDs",
            "Add peer", "Add lower-privilege user", "Make primary user", "Scan as", "Refresh as all users",
            "Add user", "Sign in all", "Compared users", "Scan warnings", "Extension scan workers",
            SignedInConsentOption.LABEL);
    private static final List<String> CROSS_IDENTITY_TEXTS = List.of("Private marker",
            "Finding it in another user's reply", "Compared user", "do not compare users");

    private final McpScannerTabFixture fixture = new McpScannerTabFixture();
    private McpScannerTab tab;

    @BeforeEach
    void connectInCommunity() throws Exception {
        fixture.professional = false;
        tab = fixture.connected(oneItemOfEachKind());
    }

    @Test
    void buildsNoScanCheckAccessOrScansParts() throws Exception {
        List<Component> everything = everyComponentInEverySection(tab);

        assertThat(everything).noneMatch(component -> PROFESSIONAL_PARTS.stream()
                .anyMatch(part -> part.isInstance(component)));
    }

    @Test
    void offersNoChecksOrRequestsSection() throws Exception {
        assertThat(fromEdt(() -> drawer(tab).sectionOrder()))
                .doesNotContain(McpScannerTab.CHECKS_SECTION, McpScannerTab.REQUESTS_SECTION);
    }

    @Test
    void showsNoScanCompareOrCollectIdsControls() throws Exception {
        List<String> texts = texts(everyComponentInEverySection(tab));

        assertThat(texts).noneMatch(text -> PROFESSIONAL_TEXTS.stream()
                .anyMatch(professional -> isLabelled(text, professional)));
    }

    @Test
    void showsNoCrossIdentityControls() throws Exception {
        List<String> texts = texts(everyComponentInEverySection(tab));

        assertThat(texts).noneMatch(text -> CROSS_IDENTITY_TEXTS.stream().anyMatch(text::contains));
    }

    @Test
    void aMalformedItemIsNotDescribedInScanTerms() throws Exception {
        String problems = fromEdt(() -> {
            tools(tab).populate(List.of(new McpToolDefinition(null, null, null)));
            tools(tab).table().setRowSelectionInterval(0, 0);
            return tools(tab).detailPanel().problemsLine().getText();
        });

        assertThat(problems).startsWith("Malformed: ").endsWith(".").doesNotContainIgnoringCase("scan");
    }

    @Test
    void inventoryDetailsExplainNoScanArguments() throws Exception {
        assertThat(texts(everyComponentInEverySection(tab))).noneMatch(text -> text.startsWith("Scans "));
    }

    @Test
    void keepsThePrimaryUserForSignIn() throws Exception {
        assertThat(texts(everyComponentInEverySection(tab))).contains("Primary user");
    }

    @Test
    void showsTheProfessionalNoteAndSupportLinksWhereTheScanBarWas() throws Exception {
        List<Component> everything = fromEdt(() -> SwingTree.descendants(tab));

        assertThat(texts(everything)).contains(ScanUnavailable.NOTE);
        assertThat(everything).filteredOn(HyperlinkLabel.class::isInstance).map(c -> ((JLabel) c).getText())
                .contains(SupportLinks.REPORT_BUG, SupportLinks.REQUEST_FEATURE);
    }

    @Test
    void theUsersLabelCountsOnlyThePrimaryUser() throws Exception {
        fixture.identities.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        fixture.identities.add(Identity.create("carol", IdentityRole.LOWER, IdentityAuthKind.BEARER));
        onEdt(() -> { });

        assertThat(fromEdt(() -> drawer(tab).labelOf(McpScannerTab.USERS_SECTION))).isEqualTo("Users (1)");
    }

    @Test
    void offersNoWriteReplayApproval() {
        assertThat(tab.writeReplayApproval()).isEmpty();
    }

    @Test
    void opensANonScanSectionByDefault() throws Exception {
        McpScannerTab fresh = fromEdt(fixture::newTab);

        assertThat(fromEdt(() -> drawer(fresh).expandedSection())).contains(McpScannerTab.USERS_SECTION);
    }

    @Test
    void inventoryTablesHaveNoTickBoxColumn() throws Exception {
        onEdt(() -> tickableInventoryPanels(tab).forEach(panel -> assertThat(tickBoxColumnsOf(panel)).isEmpty()));
    }

    @Test
    void sendsToRepeaterAndOrganizer() throws Exception {
        assertThat(toolRowMenuTexts(tab)).contains("Send to Repeater", "Send to Organizer");
    }

    @Test
    void asksTheServerForValues() throws Exception {
        assertThat(promptArgumentMenuLabel(tab)).contains(ValueCompletion.MENU_LABEL);
    }
}
