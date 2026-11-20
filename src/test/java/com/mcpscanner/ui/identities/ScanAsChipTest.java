package com.mcpscanner.ui.identities;

import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.testutil.SwingTree;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.swing.JCheckBoxMenuItem;
import javax.swing.JLabel;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButtonMenuItem;
import javax.swing.JSeparator;
import java.awt.Component;
import java.util.List;
import java.util.Optional;

import static com.mcpscanner.ui.identities.IdentitiesHarness.fromEdt;
import static com.mcpscanner.ui.identities.IdentitiesHarness.onEdt;
import static org.assertj.core.api.Assertions.assertThat;

class ScanAsChipTest {

    private final IdentitiesHarness harness = new IdentitiesHarness();
    private final List<String> errors = new java.util.ArrayList<>();

    @AfterEach
    void tearDown() {
        harness.close();
    }

    @Test
    void isShownEvenWhileThePrimaryUserIsTheOnlyUser() throws Exception {
        ScanAsChip chip = chip();

        assertThat(fromEdt(chip::isVisible)).isTrue();
        assertThat(fromEdt(chip::getText)).isEqualTo("Scan as User 1 · no comparison ▾");
    }

    @Test
    void namesTheScanAsUserAndTheComparedUsers() throws Exception {
        signedIn(harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        signedIn(harness.add("carol", IdentityRole.LOWER, IdentityAuthKind.BEARER));
        ScanAsChip chip = chip();

        assertThat(fromEdt(chip::isVisible)).isTrue();
        assertThat(fromEdt(chip::getText)).isEqualTo("Scan as User 1 · compare bob, carol + No credential + Fake token ▾");
        assertThat((String) fromEdt(chip::getToolTipText)).isEqualTo(ScanAsChip.COMPARING)
                .contains("No credential").contains("Fake token").doesNotContain("Anonymous");
    }

    @Test
    void saysNoComparedUserAndThatCheckAccessStillComparesWithoutAndWithAFakeCredential() throws Exception {
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        harness.registry.update(bob.withCompared(false));
        ScanAsChip chip = chip();

        assertThat(fromEdt(chip::getText)).isEqualTo("Scan as User 1 · no comparison ▾");
        assertThat((String) fromEdt(chip::getToolTipText))
                .isEqualTo("Check access replays each item with No credential and a Fake token; "
                        + "tick Compare on another user to compare signed-in users too.");
    }

    @Test
    void itsMenuListsScanAsRadiosThenASeparatorThenCompareTicks() throws Exception {
        signedIn(harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        ScanAsChip chip = chip();

        List<String> entries = fromEdt(() -> SwingTree.descendants(chip.menu()).stream()
                .filter(component -> component.getParent() instanceof JPopupMenu)
                .map(ScanAsChipTest::describe).toList());

        assertThat(entries).containsExactly("heading Scan as", "radio User 1 on", "radio bob off", "separator",
                "heading Compare", "tick bob on");
    }

    @Test
    void ticksToggleWhetherEachUserIsCompared() throws Exception {
        Identity bob = signedIn(harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        signedIn(harness.add("carol", IdentityRole.LOWER, IdentityAuthKind.BEARER));
        ScanAsChip chip = chip();

        onEdt(() -> ticks(chip).get(0).doClick());
        onEdt(() -> { });

        assertThat(harness.identity(bob.id()).compared()).isFalse();
        assertThat(fromEdt(chip::getText)).isEqualTo("Scan as User 1 · compare carol + No credential + Fake token ▾");
    }

    @Test
    void aTickForAUserRemovedMeanwhileReportsTheRefusalInsteadOfThrowing() throws Exception {
        Identity bob = signedIn(harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        ScanAsChip chip = chip();
        JCheckBoxMenuItem tick = fromEdt(() -> ticks(chip).get(0));
        harness.registry.remove(bob.id());

        onEdt(tick::doClick);

        assertThat(errors).hasSize(1);
    }

    @Test
    void usersWithoutCredentialsAreDisabledAndSayWhy() throws Exception {
        harness.add("Peer", IdentityRole.PEER, IdentityAuthKind.BEARER);
        ScanAsChip chip = chip();

        JRadioButtonMenuItem radio = fromEdt(() -> radios(chip).get(1));
        JCheckBoxMenuItem tick = fromEdt(() -> ticks(chip).get(0));
        assertThat(radio.getText()).isEqualTo("Peer " + ScanAsChip.NEEDS_CREDENTIALS);
        assertThat(radio.isEnabled()).isFalse();
        assertThat(tick.getText()).isEqualTo("Peer " + ScanAsChip.NEEDS_CREDENTIALS);
        assertThat(tick.isEnabled()).isFalse();
    }

    @Test
    void choosingScanAsWhileDisconnectedSwitchesTheConnectAsUser() throws Exception {
        Identity bob = signedIn(harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        ScanAsChip chip = chip();

        onEdt(() -> radios(chip).get(1).doClick());
        onEdt(() -> { });

        assertThat(harness.registry.primaryUser().id()).isEqualTo(bob.id());
        assertThat(harness.reconnectPrompts).isEmpty();
        assertThat(fromEdt(chip::getText)).startsWith("Scan as bob · ");
    }

    @Test
    void choosingScanAsWhileConnectedSharesTheReconnectConfirmation() throws Exception {
        Identity bob = signedIn(harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER));
        harness.connected.set(true);
        ScanAsChip chip = chip();

        onEdt(() -> radios(chip).get(1).doClick());

        assertThat(harness.reconnectPrompts).containsExactly("User 1 -> bob");
        assertThat(harness.registry.primaryUser().id()).isEqualTo(bob.id());
        assertThat(harness.reconnects).hasValue(1);
    }

    @Test
    void aDisposedChipStopsFollowingTheRegistry() throws Exception {
        ScanAsChip chip = chip();

        String before = fromEdt(chip::getText);
        onEdt(chip::dispose);
        Identity bob = harness.add("bob", IdentityRole.PEER, IdentityAuthKind.BEARER);
        harness.registry.setCredential(bob.id(), new com.mcpscanner.auth.BearerTokenAuthStrategy("t"));
        onEdt(() -> { });

        assertThat(fromEdt(chip::getText)).isEqualTo(before);
    }

    private ScanAsChip chip() throws Exception {
        IdentityCommands commands = new IdentityCommands(harness.services,
                error -> Optional.ofNullable(error).ifPresent(errors::add), selected -> { });
        return fromEdt(() -> new ScanAsChip(harness.services, commands));
    }

    private static List<JRadioButtonMenuItem> radios(ScanAsChip chip) {
        return SwingTree.descendants(chip.menu()).stream().filter(JRadioButtonMenuItem.class::isInstance)
                .map(JRadioButtonMenuItem.class::cast).toList();
    }

    private static List<JCheckBoxMenuItem> ticks(ScanAsChip chip) {
        return SwingTree.descendants(chip.menu()).stream().filter(JCheckBoxMenuItem.class::isInstance)
                .map(JCheckBoxMenuItem.class::cast).toList();
    }

    private static String describe(Component component) {
        if (component instanceof JRadioButtonMenuItem radio) {
            return "radio " + radio.getText() + (radio.isSelected() ? " on" : " off");
        }
        if (component instanceof JCheckBoxMenuItem tick) {
            return "tick " + tick.getText() + (tick.isSelected() ? " on" : " off");
        }
        if (component instanceof JLabel label) {
            return "heading " + label.getText();
        }
        return component instanceof JSeparator ? "separator" : component.getClass().getSimpleName();
    }

    private Identity signedIn(Identity identity) {
        harness.registry.setCredential(identity.id(), new BearerTokenAuthStrategy(identity.name() + "-token"));
        return identity;
    }
}
