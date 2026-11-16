package com.mcpscanner.ui.identities;

import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.OwnedValues;
import com.mcpscanner.identity.discovery.IdentityListingsFixture;
import com.mcpscanner.testutil.SwingTree;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Timeout;

import javax.swing.JButton;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.IntStream;

import static com.mcpscanner.ui.identities.IdentitiesHarness.fromEdt;
import static com.mcpscanner.ui.identities.IdentitiesHarness.onEdt;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@Timeout(30)
class UsersPanelTest {

    private final IdentitiesHarness harness = new IdentitiesHarness();
    private UsersPanel panel;

    @AfterEach
    void tearDown() {
        harness.close();
    }

    @Test
    void theTableListsTheComparedUsersThenAnonymousAlwaysIncluded() throws Exception {
        harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        harness.add("carol", IdentityRole.LOWER, IdentityAuthKind.OAUTH);
        open();

        assertThat(fromEdt(() -> IntStream.range(0, panel.table().getColumnCount())
                .mapToObj(column -> String.valueOf(panel.table().getColumnModel().getColumn(column).getHeaderValue()))
                .toList())).containsExactly("Compare", "Name", "Access", "Auth", "Status");
        assertThat(column(IdentityTableModel.NAME)).containsExactly("bob", "carol", "Anonymous");
        assertThat(column(IdentityTableModel.ACCESS)).containsExactly("Same (peer)", "Less access", "—");
        assertThat(column(IdentityTableModel.COMPARE)).containsExactly(true, true, true);
        assertThat(fromEdt(() -> panel.table().getModel().isCellEditable(0, IdentityTableModel.COMPARE))).isTrue();
        assertThat(fromEdt(() -> panel.table().getModel().isCellEditable(2, IdentityTableModel.COMPARE))).isFalse();
        assertThat(cell(2, IdentityTableModel.STATUS)).isEqualTo("Always included");
    }

    @Test
    void theSectionsArePrimaryUserAndComparedUsers() throws Exception {
        open();

        assertThat(fromEdt(panel::headings)).containsExactly("Primary user", "Compared users");
        assertThat(fromEdt(() -> panel.primaryEditor().nameField().getText())).isEqualTo("User 1");
        assertThat(fromEdt(panel::noteText)).isEqualTo(UsersPanel.NO_COMPARED_USERS);
    }

    @Test
    void thePrimaryUserIsEditedInItsOwnSectionWithoutAccessOrCompare() throws Exception {
        harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();

        onEdt(() -> panel.primaryEditor().markerField().setText("ALICE-PRIVATE"));
        flush();

        assertThat(harness.userOne().privateMarker()).contains("ALICE-PRIVATE");
        assertThat(harness.config.identitiesJson()).contains("ALICE-PRIVATE");
        assertThat(fromEdt(() -> visible(panel.primaryEditor().roleCombo()))).isFalse();
        assertThat(fromEdt(() -> visible(panel.primaryEditor().makePrimaryButton()))).isFalse();
    }

    @Test
    void selectingAComparedUserOpensItsEditorWithMakePrimaryUser() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.NONE);
        open();
        onEdt(() -> panel.select(bob.id()));

        assertThat(fromEdt(panel::showingComparedEditor)).isTrue();
        assertThat(fromEdt(() -> panel.comparedEditor().title())).isEqualTo("Compared user: bob");

        onEdt(() -> panel.comparedEditor().makePrimaryButton().doClick());
        flush();

        assertThat(harness.registry.isPrimary(bob.id())).isTrue();
        assertThat(fromEdt(() -> panel.primaryEditor().nameField().getText())).isEqualTo("bob");
        assertThat(column(IdentityTableModel.NAME)).containsExactly("User 1", "Anonymous");
    }

    @Test
    void detectAutomaticallyIsOfferedOnlyToThePrimaryUserWithItsHelp() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();
        onEdt(() -> panel.select(bob.id()));

        assertThat(fromEdt(() -> panel.primaryEditor().authLabels()))
                .containsExactly("Detect automatically", "None", "Bearer token", "Custom headers", "OAuth sign-in");
        assertThat(fromEdt(() -> panel.primaryEditor().kindHelp())).isEqualTo(AuthLabels.DETECT_HELP);
        assertThat(fromEdt(() -> panel.comparedEditor().authLabels()))
                .containsExactly("None", "Bearer token", "Custom headers", "OAuth sign-in");
    }

    @Test
    void aTokenSavedOutsideTheEditorShowsMaskedInThePrimaryEditor() throws Exception {
        harness.registry.update(harness.userOne().withAuthKind(IdentityAuthKind.BEARER));
        open();

        harness.credentials.credentials().supplyToken(harness.userOne().id(), "saved-elsewhere");
        flush();

        assertThat(fromEdt(() -> panel.primaryEditor().credentials().tokenField().value()))
                .isEqualTo("saved-elsewhere");
        assertThat(fromEdt(() -> panel.primaryEditor().credentials().tokenField().revealed())).isFalse();
    }

    @Test
    void aDetectingPrimaryUserThatResolvedToOAuthShowsTheOutcomeAndSignInAgain() throws Exception {
        harness.registry.recordDetected(harness.userOne().id(), IdentityAuthKind.OAUTH);
        harness.registry.setCredential(harness.userOne().id(), new com.mcpscanner.auth.BearerTokenAuthStrategy("s"));
        open();

        assertThat(fromEdt(() -> panel.primaryEditor().kindHelp()))
                .isEqualTo("Detected: OAuth 2.1 on the last Connect.");
        assertThat(fromEdt(() -> visible(panel.primaryEditor().credentials().signInButton()))).isTrue();
        assertThat(fromEdt(() -> panel.primaryEditor().credentials().signInButton().getText()))
                .isEqualTo("Sign in again");
        assertThat(fromEdt(() -> visible(panel.primaryEditor().credentials().issuerField()))).isFalse();
    }

    @Test
    void focusingThePrimaryCredentialsTargetsItsTokenOrItsAuthChoice() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();
        onEdt(() -> panel.select(bob.id()));

        onEdt(panel::focusPrimaryCredentials);
        assertThat(fromEdt(() -> panel.table().getSelectedRow())).isEqualTo(-1);
        assertThat(fromEdt(() -> panel.primaryEditor().credentialFocusTarget()))
                .isSameAs(fromEdt(() -> panel.primaryEditor().authCombo()));

        harness.registry.update(harness.userOne().withAuthKind(IdentityAuthKind.BEARER));
        flush();
        assertThat(fromEdt(() -> panel.primaryEditor().credentialFocusTarget()))
                .isSameAs(fromEdt(() -> panel.primaryEditor().credentials().tokenField().textField()));
    }

    @Test
    void selectingAnonymousExplainsIt() throws Exception {
        open();
        onEdt(() -> panel.table().setRowSelectionInterval(0, 0));

        assertThat(fromEdt(panel::noteText)).isEqualTo(UsersPanel.ANONYMOUS_NOTE);
        assertThat(fromEdt(() -> panel.removeButton().isEnabled())).isFalse();
    }

    @Test
    void addMenuCreatesBearerCustomHeaderOAuthAndNoCredentialUsers() throws Exception {
        open();

        click(menuItem("Bearer token"));
        click(menuItem("Custom headers"));
        click(menuItem("OAuth sign-in"));
        click(menuItem("No credentials"));
        flush();

        assertThat(harness.registry.identities()).extracting(Identity::authKind)
                .containsExactly(IdentityAuthKind.DETECT, IdentityAuthKind.BEARER, IdentityAuthKind.CUSTOM_HEADERS,
                        IdentityAuthKind.OAUTH, IdentityAuthKind.NONE);
        assertThat(harness.registry.identities()).extracting(Identity::name).doesNotHaveDuplicates();
    }

    @Test
    void addMenuDuplicatesTheSelectedIdentity() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();
        onEdt(() -> panel.select(bob.id()));

        click(menuItem("Duplicate bob"));
        flush();

        assertThat(harness.registry.identities()).extracting(Identity::name).containsExactly("User 1", "bob", "bob copy");
    }

    @Test
    void addingAnIdentityWhileAnotherIsSelectedOpensTheNewOneInTheEditor() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();
        onEdt(() -> panel.select(bob.id()));

        click(menuItem("Bearer token"));
        flush();

        assertThat(fromEdt(() -> panel.comparedEditor().nameField().getText())).isEqualTo("User");
        assertThat(fromEdt(() -> selectedName())).isEqualTo("User");
    }

    @Test
    void theToolbarIsOneRowOfThreeEqualButtons() throws Exception {
        open();
        onEdt(() -> {
            panel.setSize(440, 700);
            SwingTree.layOut(panel);
        });

        List<JButton> buttons = List.of(panel.addButton(), panel.signInAllButton(), panel.removeButton());
        assertThat(fromEdt(() -> buttons.stream().map(JButton::getText).toList()))
                .containsExactly("Add user ▾", "Sign in all", "Remove");
        List<java.awt.Rectangle> bounds = fromEdt(() -> buttons.stream().map(JButton::getBounds).toList());
        assertThat(bounds).allSatisfy(bound -> {
            assertThat(bound.getSize()).isEqualTo(bounds.get(0).getSize());
            assertThat(bound.y).isEqualTo(bounds.get(0).y);
        });
        assertThat(bounds.get(0).width).isPositive();
        assertThat(fromEdt(() -> SwingTree.descendants(panel).stream().filter(JButton.class::isInstance)
                .map(button -> ((JButton) button).getText()).toList())).doesNotContain("Duplicate", "Connect as", "Add peer");
    }

    @Test
    void theAddMenuItemsArePlainText() throws Exception {
        open();

        List<String> items = fromEdt(() -> SwingTree.descendants(panel.addMenu()).stream()
                .filter(JMenuItem.class::isInstance).map(item -> ((JMenuItem) item).getText()).toList());

        assertThat(items).containsExactly("Bearer token", "Custom headers", "OAuth sign-in", "No credentials",
                "Duplicate");
        assertThat(items).noneMatch(text -> text.contains("<"));
    }

    @Test
    void duplicatingOpensTheCopyInTheEditor() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();
        onEdt(() -> panel.select(bob.id()));

        JMenuItem duplicate = menuItem("Duplicate bob");
        onEdt(duplicate::doClick);
        flush();

        assertThat(fromEdt(() -> panel.comparedEditor().nameField().getText())).isEqualTo("bob copy");
    }

    @Test
    void aDisposedPanelStopsFollowingTheRegistry() throws Exception {
        open();
        int rows = fromEdt(() -> panel.table().getRowCount());

        onEdt(() -> panel.dispose());
        harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        flush();

        assertThat(fromEdt(() -> panel.table().getRowCount())).isEqualTo(rows);
    }

    @Test
    void duplicateAndRemoveActOnTheSelectedIdentity() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();
        onEdt(() -> panel.select(bob.id()));

        JMenuItem duplicate = menuItem("Duplicate bob");
        onEdt(duplicate::doClick);
        flush();
        onEdt(() -> panel.select(bob.id()));
        onEdt(() -> panel.removeButton().doClick());
        flush();

        assertThat(harness.registry.identities()).extracting(Identity::name).containsExactly("User 1", "bob copy");
    }

    @Test
    void editsToNameRoleAndMarkerPersistAndKeepOwnedValues() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        OwnedValues owned = OwnedValues.entered(Map.of("doc_id", "d-bob-1"));
        harness.registry.update(bob.withOwnedValues(owned));
        open();
        onEdt(() -> panel.select(bob.id()));

        onEdt(() -> {
            IdentityEditor editor = panel.comparedEditor();
            editor.nameField().setText("robert");
            editor.nameField().postActionEvent();
            editor.roleCombo().setSelectedItem(IdentityRole.LOWER);
            editor.markerField().setText("ALICE-ONLY");
        });
        flush();

        Identity edited = harness.identity(bob.id());
        assertThat(edited.name()).isEqualTo("robert");
        assertThat(edited.role()).isEqualTo(IdentityRole.LOWER);
        assertThat(edited.privateMarker()).contains("ALICE-ONLY");
        assertThat(edited.ownedValues()).isEqualTo(owned);
        assertThat(harness.config.identitiesJson()).contains("robert", "ALICE-ONLY", "d-bob-1");
    }

    @Test
    void aDuplicateNameIsRefusedWithAReason() throws Exception {
        harness.add("alice2", IdentityRole.PEER, IdentityAuthKind.BEARER);
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();
        onEdt(() -> panel.select(bob.id()));

        onEdt(() -> {
            panel.comparedEditor().nameField().setText("alice2");
            panel.comparedEditor().nameField().postActionEvent();
        });
        flush();

        assertThat(harness.identity(bob.id()).name()).isEqualTo("bob");
        assertThat(fromEdt(panel::errorText)).contains("already exists");
    }

    @Test
    void aTypedTokenBecomesTheLiveCredentialAndIsNeverPersisted() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();
        onEdt(() -> panel.select(bob.id()));
        assertThat(cell(0, IdentityTableModel.STATUS)).isEqualTo("▲ Token needed");

        onEdt(() -> panel.comparedEditor().credentials().tokenField().setValue("bob-secret-token"));
        flush();

        assertThat(harness.registry.credential(bob.id())).get()
                .satisfies(credential -> assertThat(credential.headers())
                        .containsEntry("Authorization", "Bearer bob-secret-token"));
        assertThat(harness.config.identitiesJson()).doesNotContain("bob-secret-token");
        assertThat(cell(0, IdentityTableModel.STATUS)).isEqualTo("● Ready");
    }

    @Test
    void theTokenIsMaskedAndReMaskedWhenTheSelectionChanges() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        Identity carol = harness.add("carol", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();
        onEdt(() -> panel.select(bob.id()));
        assertThat(fromEdt(() -> panel.comparedEditor().credentials().tokenField().revealed())).isFalse();

        onEdt(() -> panel.comparedEditor().credentials().tokenField().reveal(true));
        onEdt(() -> panel.select(carol.id()));

        assertThat(fromEdt(() -> panel.comparedEditor().credentials().tokenField().revealed())).isFalse();
    }

    @Test
    void clearingTheTokenDropsTheCredential() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();
        onEdt(() -> panel.select(bob.id()));

        onEdt(() -> panel.comparedEditor().credentials().tokenField().setValue("bob-secret-token"));
        onEdt(() -> panel.comparedEditor().credentials().tokenField().setValue(""));
        flush();

        assertThat(harness.registry.credential(bob.id())).isEmpty();
    }

    @Test
    void customHeaderNamesPersistButTheirValuesStayInMemory() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.CUSTOM_HEADERS);
        open();
        onEdt(() -> panel.select(bob.id()));

        onEdt(() -> panel.comparedEditor().credentials().headerValues().setHeaders(Map.of("X-Api-Key", "bob-key-123")));
        flush();

        assertThat(harness.identity(bob.id()).headerNames()).containsExactly("X-Api-Key");
        assertThat(harness.registry.credential(bob.id())).get()
                .satisfies(credential -> assertThat(credential.headers()).containsEntry("X-Api-Key", "bob-key-123"));
        assertThat(harness.config.identitiesJson()).contains("X-Api-Key").doesNotContain("bob-key-123");
    }

    @Test
    void theCredentialInputFollowsTheRequirement() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();
        onEdt(() -> panel.select(bob.id()));
        assertThat(fromEdt(() -> visible(panel.comparedEditor().credentials().tokenField()))).isTrue();

        onEdt(() -> panel.comparedEditor().authCombo().setSelectedItem(IdentityAuthKind.NONE));
        flush();
        assertThat(fromEdt(() -> visible(panel.comparedEditor().credentials().tokenField()))).isFalse();
        assertThat(fromEdt(() -> visible(panel.comparedEditor().credentials().signInButton()))).isFalse();

        onEdt(() -> panel.comparedEditor().authCombo().setSelectedItem(IdentityAuthKind.OAUTH));
        flush();

        assertThat(harness.identity(bob.id()).authKind()).isEqualTo(IdentityAuthKind.OAUTH);
        assertThat(fromEdt(() -> visible(panel.comparedEditor().credentials().signInButton()))).isTrue();
        assertThat(fromEdt(() -> visible(panel.comparedEditor().credentials().tokenField()))).isFalse();

        harness.sharedClient.set(Optional.empty());
        onEdt(panel::refresh);
        assertThat(fromEdt(() -> panel.comparedEditor().credentials().note())).contains("Enter a valid OAuth issuer URL");

        onEdt(() -> panel.comparedEditor().credentials().issuerField().setText("https://other-as.example"));
        flush();
        assertThat(harness.identity(bob.id()).oauth().issuer()).isEqualTo("https://other-as.example");
        assertThat(fromEdt(() -> visible(panel.comparedEditor().credentials().signInButton()))).isTrue();
    }

    @Test
    void theAuthChoicesAreNoneBearerCustomHeadersAndOAuth() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();
        onEdt(() -> panel.select(bob.id()));

        assertThat(fromEdt(() -> panel.comparedEditor().authLabels()))
                .containsExactly("None", "Bearer token", "Custom headers", "OAuth sign-in");
    }

    @Test
    void signInShowsProgressAndThenReady() throws Exception {
        harness.holdSignIns.set(true);
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.OAUTH);
        open();
        onEdt(() -> panel.select(bob.id()));
        assertThat(cell(0, IdentityTableModel.STATUS)).isEqualTo("▲ Sign in");

        onEdt(() -> panel.comparedEditor().credentials().signInButton().doClick());
        await().until(() -> fromEdt(() -> panel.comparedEditor().credentials().signInStatus()).equals("Signing in…"));
        assertThat(fromEdt(() -> panel.comparedEditor().credentials().signInButton().getText())).isEqualTo("Cancel");

        harness.signInGate.countDown();
        await().until(() -> cell(0, IdentityTableModel.STATUS).equals("● Ready"));
        assertThat(fromEdt(() -> panel.comparedEditor().credentials().signInStatus())).isEqualTo("● Signed in");
    }

    @Test
    void signInAllQueuesEveryIdentityThatSignsInThroughTheBrowser() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.OAUTH);
        Identity carol = harness.add("carol", IdentityRole.LOWER, IdentityAuthKind.OAUTH);
        open();

        onEdt(() -> panel.signInAllButton().doClick());

        await().until(() -> harness.registry.credential(bob.id()).isPresent()
                && harness.registry.credential(carol.id()).isPresent());
    }

    @Test
    void theSessionLineShowsWhatTheIdentityListedOrWhyDiscoveryFailed() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();
        onEdt(() -> panel.select(bob.id()));

        IdentityListingsFixture.listed(harness.listings, bob.id(), Set.of("a", "b"), Set.of("notes://x"));
        await().until(() -> fromEdt(() -> panel.comparedEditor().sessionLine()).equals(
                "Own MCP session: 2 tools, 1 resource listed"));

        IdentityListingsFixture.failed(harness.listings, bob.id(), "HTTP 401 from the server");
        await().until(() -> fromEdt(() -> panel.comparedEditor().sessionLine()).equals(
                "Discovery failed: HTTP 401 from the server"));
    }

    @Test
    void typingACredentialNeverDiscoversUntilDiscoverIsPressed() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        harness.connectDiscovery();
        open();
        onEdt(() -> panel.select(bob.id()));
        assertThat(fromEdt(() -> panel.comparedEditor().discoverButton().isEnabled())).isFalse();

        typeToken("b");
        typeToken("bo");
        typeToken("bob");
        harness.runDiscoveries();

        assertThat(harness.discoveredWith).isEmpty();
        assertThat(cell(0, IdentityTableModel.STATUS)).isEqualTo(IdentityStatusText.NOT_DISCOVERED);
        assertThat(fromEdt(() -> panel.comparedEditor().sessionLine())).isEqualTo(IdentityStatusText.NOT_DISCOVERED);
        assertThat(fromEdt(() -> panel.comparedEditor().discoverButton().isEnabled())).isTrue();
    }

    @Test
    void theStatusColumnFollowsDiscoveryFromThePressedButtonToTheListing() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        harness.connectDiscovery();
        open();
        onEdt(() -> panel.select(bob.id()));
        typeToken("bob");

        onEdt(() -> panel.comparedEditor().discoverButton().doClick());
        await().until(() -> cell(0, IdentityTableModel.STATUS).equals(IdentityStatusText.DISCOVERING));

        harness.runDiscoveries();
        await().until(() -> cell(0, IdentityTableModel.STATUS).equals("● Listed 2 tools, 0 resources"));
        assertThat(harness.discoveredWith).containsExactly("Bearer bob");
    }

    @Test
    void editingADiscoveredCredentialMarksTheStatusStaleUntilDiscoveredAgain() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        harness.connectDiscovery();
        open();
        onEdt(() -> panel.select(bob.id()));
        typeToken("bob");
        onEdt(() -> panel.comparedEditor().discoverButton().doClick());
        harness.runDiscoveries();

        typeToken("bob-2");

        String stale = IdentityStatusText.WARNING_MARK + IdentityStatusText.CREDENTIAL_CHANGED;
        await().until(() -> cell(0, IdentityTableModel.STATUS).equals(stale));
        assertThat(fromEdt(() -> panel.comparedEditor().sessionLine()))
                .isEqualTo(IdentityStatusText.CREDENTIAL_CHANGED);
        harness.runDiscoveries();
        assertThat(harness.discoveredWith).containsExactly("Bearer bob");

        onEdt(() -> panel.comparedEditor().discoverButton().doClick());
        harness.runDiscoveries();
        await().until(() -> cell(0, IdentityTableModel.STATUS).equals("● Listed 2 tools, 0 resources"));
        assertThat(harness.discoveredWith).containsExactly("Bearer bob", "Bearer bob-2");
    }

    @Test
    void theStatusColumnShowsWhyDiscoveryFailed() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();
        onEdt(() -> panel.select(bob.id()));
        typeToken("bob");

        IdentityListingsFixture.failed(harness.listings, bob.id(), "HTTP 401 from the server");

        await().until(() -> cell(0, IdentityTableModel.STATUS).equals("▲ Failed: HTTP 401 from the server"));
    }

    @Test
    void discoverIsDisabledUntilConnected() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();
        onEdt(() -> panel.select(bob.id()));
        typeToken("bob");

        assertThat(fromEdt(() -> panel.comparedEditor().discoverButton().isEnabled())).isFalse();
        assertThat(fromEdt(() -> panel.comparedEditor().discoverButton().getToolTipText())).isEqualTo("Connect first");
    }

    @Test
    void tickingCompareInTheTableUpdatesTheIdentity() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        open();

        onEdt(() -> panel.table().getModel().setValueAt(false, 0, IdentityTableModel.COMPARE));
        flush();

        assertThat(harness.identity(bob.id()).compared()).isFalse();
    }

    private String selectedName() {
        return String.valueOf(panel.table().getValueAt(panel.table().getSelectedRow(), IdentityTableModel.NAME));
    }

    @Test
    void inANarrowDrawerTheStatusReadsInFullAndTheNameGivesWay() throws Exception {
        harness.add("Lower-privilege user", IdentityRole.LOWER, IdentityAuthKind.BEARER);
        open();

        onEdt(() -> {
            javax.swing.JTable table = panel.table();
            table.setSize(340, table.getHeight());
            table.doLayout();
            int status = table.getColumnModel().getColumn(IdentityTableModel.STATUS).getWidth();
            for (int row = 0; row < table.getRowCount(); row++) {
                assertThat(status).as("status of row %d", row).isGreaterThanOrEqualTo(table.prepareRenderer(
                        table.getCellRenderer(row, IdentityTableModel.STATUS), row, IdentityTableModel.STATUS)
                        .getPreferredSize().width);
            }
            int name = table.getColumnModel().getColumn(IdentityTableModel.NAME).getWidth();
            assertThat(name).isGreaterThanOrEqualTo(table.getTableHeader().getDefaultRenderer()
                    .getTableCellRendererComponent(table, "Name", false, false, -1, IdentityTableModel.NAME)
                    .getPreferredSize().width);
            assertThat(java.util.stream.IntStream.range(0, table.getColumnCount())
                    .map(column -> table.getColumnModel().getColumn(column).getWidth()).sum()).isEqualTo(340);
        });
    }

    @Test
    void theComparedUsersTableFitsEveryHeaderAndCellAtTheDefaultDrawerWidth() throws Exception {
        harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        harness.add("Lower-privilege user", IdentityRole.LOWER, IdentityAuthKind.BEARER);
        open();

        onEdt(() -> {
            javax.swing.JTable table = panel.table();
            javax.swing.JScrollPane scroll = (javax.swing.JScrollPane) SwingUtilities.getAncestorOfClass(
                    javax.swing.JScrollPane.class, table);
            scroll.setSize(430, 200);
            scroll.doLayout();
            scroll.getViewport().doLayout();
            table.doLayout();
            for (int column = 0; column < table.getColumnCount(); column++) {
                int width = table.getColumnModel().getColumn(column).getWidth();
                java.awt.Component header = table.getTableHeader().getDefaultRenderer()
                        .getTableCellRendererComponent(table, table.getColumnName(column), false, false, -1, column);
                assertThat(width).as("header of column %s", table.getColumnName(column))
                        .isGreaterThanOrEqualTo(header.getPreferredSize().width);
                for (int row = 0; row < table.getRowCount(); row++) {
                    java.awt.Component cell = table.prepareRenderer(table.getCellRenderer(row, column), row, column);
                    assertThat(width).as("row %d of column %s", row, table.getColumnName(column))
                            .isGreaterThanOrEqualTo(cell.getPreferredSize().width);
                }
            }
            assertThat(table.getColumnName(IdentityTableModel.ACCESS)).isEqualTo("Access");
            java.awt.Rectangle access = table.getTableHeader().getHeaderRect(IdentityTableModel.ACCESS);
            assertThat(table.getTableHeader().getToolTipText(new java.awt.event.MouseEvent(table.getTableHeader(),
                    0, 0, 0, access.x + 2, access.y + 2, 0, false))).isEqualTo("Access vs User 1");
        });
    }

    private void typeToken(String token) throws Exception {
        onEdt(() -> panel.comparedEditor().credentials().tokenField().setValue(token));
        flush();
    }

    private void open() throws Exception {
        onEdt(() -> panel = new UsersPanel(harness.services, GrantCredentialForms.NONE, () -> { }));
    }

    private static void flush() throws Exception {
        onEdt(() -> { });
        onEdt(() -> { });
    }

    private static void click(JMenuItem item) throws Exception {
        onEdt(item::doClick);
    }

    private JMenuItem menuItem(String prefix) throws Exception {
        JPopupMenu menu = fromEdt(panel::addMenu);
        return SwingTree.descendants(menu).stream().filter(JMenuItem.class::isInstance).map(JMenuItem.class::cast)
                .filter(item -> item.getText().startsWith(prefix)).findFirst()
                .orElseThrow(() -> new AssertionError("No menu item starting " + prefix));
    }


    private List<Object> column(int column) throws Exception {
        return fromEdt(() -> IntStream.range(0, panel.table().getRowCount())
                .mapToObj(row -> panel.table().getModel().getValueAt(row, column)).toList());
    }

    private String cell(int row, int column) throws Exception {
        return fromEdt(() -> String.valueOf(panel.table().getModel().getValueAt(row, column)));
    }

    private static boolean visible(java.awt.Component component) {
        for (java.awt.Component c = component; c != null; c = c.getParent()) {
            if (!c.isVisible()) {
                return false;
            }
            if (c instanceof IdentityEditor) {
                return true;
            }
        }
        return false;
    }
}
