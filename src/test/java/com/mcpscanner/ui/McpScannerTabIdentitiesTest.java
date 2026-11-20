package com.mcpscanner.ui;

import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.testutil.SwingTree;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.ui.identities.ConnectionIdentityLine;
import com.mcpscanner.ui.identities.CredentialPrompt;
import com.mcpscanner.ui.identities.PrimaryUserPicker;
import com.mcpscanner.ui.identities.ScanAsChip;
import org.mockito.ArgumentCaptor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import java.util.ArrayList;
import java.awt.Component;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import static com.mcpscanner.ui.McpScannerTabFixture.drawer;
import static com.mcpscanner.ui.McpScannerTabFixture.emptyInventory;
import static com.mcpscanner.ui.McpScannerTabFixture.find;
import static com.mcpscanner.ui.McpScannerTabFixture.fromEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.header;
import static com.mcpscanner.ui.McpScannerTabFixture.scanBar;
import static com.mcpscanner.ui.McpScannerTabFixture.scanButton;
import static java.time.Duration.ofMillis;
import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class McpScannerTabIdentitiesTest {

    private McpScannerTabFixture fixture;

    @BeforeEach
    void setUp() {
        fixture = new McpScannerTabFixture();
    }

    @Test
    void theDrawerListsUsersThenClientAfterChecksAndOpensOnChecks() throws Exception {
        McpScannerTab tab = fromEdt(fixture::newTab);

        assertThat(fromEdt(() -> drawer(tab).sectionOrder()))
                .containsExactly("Checks", "Users", "Client", "Requests", "Log", "Settings");
        assertThat(fromEdt(() -> drawer(tab).expandedSection())).contains("Checks");
    }

    @Test
    void theUsersTabTitleCountsTheUsers() throws Exception {
        McpScannerTab tab = fromEdt(fixture::newTab);
        assertThat(fromEdt(() -> drawer(tab).labelOf("Users"))).isEqualTo("Users (1)");

        Identity bob = fixture.identities.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        fixture.identities.add(Identity.create("carol", IdentityRole.LOWER, IdentityAuthKind.BEARER));
        fixture.identities.setCredential(bob.id(), new BearerTokenAuthStrategy("bob-token"));

        await().atMost(ofSeconds(5))
                .until(() -> fromEdt(() -> drawer(tab).labelOf("Users")).equals("Users (3)"));
    }

    @Test
    void theHeaderNamesThePrimaryUserBeforeConnectAndItsEditUsersItemOpensUsers() throws Exception {
        McpScannerTab tab = fromEdt(fixture::newTab);
        PrimaryUserPicker picker = fromEdt(() -> find(tab, PrimaryUserPicker.class));

        assertThat(fromEdt(picker::getText)).isEqualTo("User 1 · Detect automatically ▾");
        assertThat(fromEdt(() -> header(tab).primaryHint().getText()))
                .isEqualTo("Connect, discovery and Scan run as the primary user, User 1.");
        McpScannerTabFixture.onEdt(() -> pickerItem(picker, "Edit users…").doClick());
        assertThat(fromEdt(() -> drawer(tab).expandedSection())).contains("Users");
    }

    @Test
    void theScanAsChipSitsImmediatelyLeftOfScanAndIsAlwaysShown() throws Exception {
        McpScannerTab tab = fromEdt(fixture::newTab);
        ScanAsChip chip = fromEdt(() -> find(tab, ScanAsChip.class));
        assertThat(fromEdt(chip::isVisible)).isTrue();

        List<Component> bar = fromEdt(() -> Arrays.asList(scanButton(tab).getParent().getComponents()));
        assertThat(bar.indexOf(chip)).isEqualTo(bar.indexOf(fromEdt(() -> scanButton(tab))) - 1);

        Identity bob = fixture.identities.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        fixture.identities.setCredential(bob.id(), new BearerTokenAuthStrategy("bob-token"));
        await().atMost(ofSeconds(5)).until(() -> fromEdt(chip::isVisible));
        await().atMost(ofSeconds(5)).until(() -> fromEdt(chip::getText).equals("Scan as User 1 · compare bob + No credential + Fake token ▾"));
    }

    @Test
    void choosingAnotherConnectAsUserWhileConnectedReconnectsAsThatUser() throws Exception {
        Identity bob = fixture.identities.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        fixture.identities.setCredential(bob.id(), new BearerTokenAuthStrategy("bob-token"));
        List<String> prompts = new ArrayList<>();
        fixture.reconnectPrompt = (parent, user, previous) -> prompts.add(previous + " -> " + user);
        McpScannerTab tab = fixture.connected(emptyInventory());

        chooseBob(tab);

        await().atMost(ofSeconds(5)).untilAsserted(() -> verify(fixture.clientManager, times(2)).connect(any()));
        McpScannerTabFixture.awaitConnectLabel(tab, "Disconnect");
        assertThat(prompts).containsExactly("User 1 -> bob");
        verify(fixture.clientManager).disconnect();
        ArgumentCaptor<McpServerConfig> configs = ArgumentCaptor.forClass(McpServerConfig.class);
        verify(fixture.clientManager, times(2)).connect(configs.capture());
        assertThat(configs.getAllValues().get(1).auth().headers())
                .containsEntry("Authorization", "Bearer bob-token");
        assertThat(fixture.identities.primaryUser().id()).isEqualTo(bob.id());
    }

    @Test
    void switchingConnectAsWhileConnectedStopsTheRunningScansBeforeTheRosterChanges() throws Exception {
        withBob();
        fixture.reconnectPrompt = (parent, user, previous) -> true;
        List<String> connectAsWhenScansStopped = new CopyOnWriteArrayList<>();
        doAnswer(call -> connectAsWhenScansStopped.add(fixture.identities.primaryUser().name()))
                .when(fixture.scanLauncher).cancelRunningScans();
        McpScannerTab tab = fixture.connected(emptyInventory());

        chooseBob(tab);

        assertThat(connectAsWhenScansStopped).containsExactly("User 1");
        McpScannerTabFixture.awaitConnectLabel(tab, "Disconnect");
    }

    @Test
    void switchingConnectAsWhileConnectingRestartsTheConnectionAsTheChosenUser() throws Exception {
        Identity bob = withBob();
        List<String> prompts = new CopyOnWriteArrayList<>();
        fixture.reconnectPrompt = (parent, user, previous) -> prompts.add(previous + " -> " + user);
        CompletableFuture<Void> gate = new CompletableFuture<>();
        McpScannerTab tab = fixture.connecting(gate);

        chooseBob(tab);
        await().atMost(ofSeconds(5)).untilAsserted(() -> verify(fixture.clientManager, times(2)).connect(any()));
        gate.complete(null);

        McpScannerTabFixture.awaitConnectLabel(tab, "Disconnect");
        assertThat(prompts).containsExactly("User 1 -> bob");
        assertThat(lastConnection().auth().headers()).containsEntry("Authorization", "Bearer bob-token");
        assertThat(fixture.identities.primaryUser().id()).isEqualTo(bob.id());
    }

    @Test
    void theReconnectWaitsForItsDisconnectAndAConnectClickedMeanwhileIsRefused() throws Exception {
        withBob();
        fixture.reconnectPrompt = (parent, user, previous) -> true;
        McpScannerTab tab = fixture.connected(emptyInventory());
        CompletableFuture<Void> disconnecting = new CompletableFuture<>();
        doAnswer(call -> disconnecting.get()).when(fixture.clientManager).disconnect();

        chooseBob(tab);
        McpScannerTabFixture.awaitConnectLabel(tab, "Connect");
        McpScannerTabFixture.onEdt(() -> McpScannerTabFixture.click(McpScannerTabFixture.connectButton(tab)));
        verify(fixture.clientManager, times(1)).connect(any());
        disconnecting.complete(null);

        McpScannerTabFixture.awaitConnectLabel(tab, "Disconnect");
        await().during(ofMillis(500)).atMost(ofSeconds(5))
                .until(() -> fromEdt(() -> McpScannerTabFixture.connectButton(tab).getText()).equals("Disconnect"));
        verify(fixture.clientManager, times(2)).connect(any());
        assertThat(lastConnection().auth().headers()).containsEntry("Authorization", "Bearer bob-token");
    }

    @Test
    void aReconnectRequestedOnceAlreadyDisconnectedConnectsAtOnceAndLeavesNothingPending() throws Exception {
        withBob();
        AtomicReference<McpScannerTab> current = new AtomicReference<>();
        fixture.reconnectPrompt = (parent, user, previous) -> {
            McpScannerTabFixture.click(McpScannerTabFixture.connectButton(current.get()));
            return true;
        };
        current.set(fixture.connected(emptyInventory()));
        McpScannerTab tab = current.get();

        chooseBob(tab);
        McpScannerTabFixture.awaitConnectLabel(tab, "Disconnect");
        verify(fixture.clientManager, times(2)).connect(any());
        assertThat(lastConnection().auth().headers()).containsEntry("Authorization", "Bearer bob-token");

        McpScannerTabFixture.onEdt(() -> McpScannerTabFixture.click(McpScannerTabFixture.connectButton(tab)));
        await().atMost(ofSeconds(5)).untilAsserted(() -> verify(fixture.clientManager, times(2)).disconnect());
        await().during(ofMillis(500)).atMost(ofSeconds(5))
                .until(() -> fromEdt(() -> McpScannerTabFixture.connectButton(tab).getText()).equals("Connect"));
        verify(fixture.clientManager, times(2)).connect(any());
    }

    @Test
    void aNewConnectionClearsTheRefusedToolCallSignal() throws Exception {
        fixture.toolCallRefusals.toolCallRefused();
        assertThat(fixture.toolCallRefusals.refusedWithoutCredentials()).isTrue();

        fixture.connected(emptyInventory());

        assertThat(fixture.toolCallRefusals.refusedWithoutCredentials()).isFalse();
    }

    @Test
    void theHeaderNamesThePrimaryUserWithoutCredentialsAndOffersNothingWhileCurrent() throws Exception {
        McpScannerTab tab = fixture.connected(emptyInventory());

        await().atMost(ofSeconds(5)).until(() -> identityLineLabels(tab).contains("Connected as User 1 · no credentials"));
        assertThat(fromEdt(() -> identityLineButton(tab).isVisible())).isFalse();
    }

    @Test
    void addCredentialsAfterRefusedToolCallsOpensUsersOnThePrimaryUser() throws Exception {
        McpScannerTab tab = fixture.connected(emptyInventory());
        fixture.toolCallRefusals.toolCallRefused();
        await().atMost(ofSeconds(5)).until(() -> fromEdt(() -> find(tab, CredentialPrompt.class).isVisible()));

        McpScannerTabFixture.onEdt(() -> promptButton(tab, "Add credentials for User 1").doClick());
        McpScannerTabFixture.flushEdt();

        assertThat(fromEdt(() -> drawer(tab).expandedSection())).contains("Users");
        boolean tokenOffered = fromEdt(() -> SwingTree.descendants(find(tab, CredentialPrompt.class)).stream()
                .anyMatch(component -> component instanceof com.mcpscanner.ui.widgets.SecretField
                        && component.isVisible()));
        assertThat(tokenOffered).isFalse();
    }

    @Test
    void theHeaderIdentityLineHidesOnDisconnect() throws Exception {
        McpScannerTab tab = fixture.connected(emptyInventory());

        McpScannerTabFixture.onEdt(() -> McpScannerTabFixture.click(McpScannerTabFixture.connectButton(tab)));

        McpScannerTabFixture.awaitConnectLabel(tab, "Connect");
        await().atMost(ofSeconds(5)).until(() -> !fromEdt(() -> identityLine(tab).isVisible()));
    }

    @Test
    void editingTheConnectedUsersTokenReconnectsWithTheNewTokenAfterConfirming() throws Exception {
        Identity bob = withBob();
        List<String> prompts = new CopyOnWriteArrayList<>();
        fixture.reconnectPrompt = (parent, user, previous) -> prompts.add(previous + " -> " + user);
        McpScannerTab tab = fixture.connected(emptyInventory());
        chooseBob(tab);
        await().atMost(ofSeconds(5)).untilAsserted(() -> verify(fixture.clientManager, times(2)).connect(any()));
        McpScannerTabFixture.awaitConnectLabel(tab, "Disconnect");

        fixture.identities.setCredential(bob.id(), new BearerTokenAuthStrategy("bob-new-token"));
        await().atMost(ofSeconds(5)).until(() -> fromEdt(() -> identityLineButton(tab).isVisible()));
        assertThat(fromEdt(() -> identityLineButton(tab).getText())).isEqualTo("Reconnect");
        McpScannerTabFixture.onEdt(() -> identityLineButton(tab).doClick());

        await().atMost(ofSeconds(5)).untilAsserted(() -> verify(fixture.clientManager, times(3)).connect(any()));
        McpScannerTabFixture.awaitConnectLabel(tab, "Disconnect");
        assertThat(prompts).containsExactly("User 1 -> bob", "bob -> bob");
        verify(fixture.scanLauncher, times(2)).cancelRunningScans();
        assertThat(lastConnection().auth().headers()).containsEntry("Authorization", "Bearer bob-new-token");
        await().atMost(ofSeconds(5)).until(() -> !fromEdt(() -> identityLineButton(tab).isVisible()));
    }

    private static ConnectionIdentityLine identityLine(McpScannerTab tab) {
        return find(header(tab), ConnectionIdentityLine.class);
    }

    private static List<String> identityLineLabels(McpScannerTab tab) throws Exception {
        return fromEdt(() -> SwingTree.descendants(identityLine(tab)).stream().filter(JLabel.class::isInstance)
                .map(label -> ((JLabel) label).getText()).toList());
    }

    private static JButton identityLineButton(McpScannerTab tab) {
        return SwingTree.descendants(identityLine(tab)).stream().filter(JButton.class::isInstance)
                .map(JButton.class::cast).findFirst().orElseThrow();
    }

    private Identity withBob() {
        Identity bob = fixture.identities.add(Identity.create("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        fixture.identities.setCredential(bob.id(), new BearerTokenAuthStrategy("bob-token"));
        return bob;
    }

    private static void chooseBob(McpScannerTab tab) throws Exception {
        McpScannerTabFixture.onEdt(() -> pickerItem(find(tab, PrimaryUserPicker.class), "bob").doClick());
        McpScannerTabFixture.flushEdt();
    }

    private static JButton promptButton(McpScannerTab tab, String text) {
        return SwingTree.descendants(find(tab, CredentialPrompt.class)).stream().filter(JButton.class::isInstance)
                .map(JButton.class::cast).filter(button -> text.equals(button.getText())).findFirst().orElseThrow();
    }

    private static JMenuItem pickerItem(PrimaryUserPicker picker, String prefix) {
        return SwingTree.descendants(picker.menu()).stream().filter(JMenuItem.class::isInstance)
                .map(JMenuItem.class::cast).filter(item -> item.getText().startsWith(prefix)).findFirst()
                .orElseThrow(() -> new AssertionError("No picker item " + prefix));
    }

    private McpServerConfig lastConnection() throws Exception {
        ArgumentCaptor<McpServerConfig> configs = ArgumentCaptor.forClass(McpServerConfig.class);
        verify(fixture.clientManager, atLeastOnce()).connect(configs.capture());
        return configs.getValue();
    }

}
