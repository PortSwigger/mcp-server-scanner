package com.mcpscanner.ui;

import com.mcpscanner.ui.widgets.DialogOwner;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.identity.ConnectedIdentity;
import com.mcpscanner.identity.ConnectionFreshness;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.ToolCallRefusals;
import com.mcpscanner.identity.credentials.IdentityCredentialServices;
import com.mcpscanner.identity.credentials.PrimaryUserCredentials;
import com.mcpscanner.ui.identities.ConnectionIdentityLine;
import com.mcpscanner.ui.identities.CredentialPrompt;
import com.mcpscanner.ui.identities.IdentityConnection;
import com.mcpscanner.ui.identities.IdentityUiServices;
import com.mcpscanner.ui.identities.PrimaryUserPicker;
import com.mcpscanner.ui.identities.ScanAsChip;
import com.mcpscanner.ui.identities.UsersMode;
import com.mcpscanner.ui.identities.UsersPanel;
import com.mcpscanner.ui.widgets.ScrollableForm;

import javax.swing.JComponent;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

final class UsersView {

    private final IdentityRegistry registry;
    private final ToolCallRefusals refusals;
    private final IdentityCredentialServices credentialServices;
    private final IdentityUiServices services;
    private final UsersMode mode;
    private final UsersPanel panel;
    private final Optional<ScanAsChip> chip;
    private final ConnectionIdentityLine connectionIdentityLine;
    private final List<Runnable> subscriptions = new ArrayList<>();
    private final Optional<PrimaryUserPicker> picker;

    UsersView(IdentityDependencies deps, IdentityConnection connection, DialogOwner dialogOwner, Component dialogParent,
              Consumer<String> declineLog, ServerConfigPanel serverConfig, Runnable openUsers,
              Runnable openOAuthClient, UsersMode mode) {
        this.mode = mode;
        this.registry = deps.registry();
        this.refusals = deps.refusals();
        this.credentialServices = deps.credentialServices().apply(new PanelAuthSettings(serverConfig),
                new SwingScopeApprovals(dialogOwner, dialogParent, declineLog));
        this.services = new IdentityUiServices(registry, credentialServices, deps.listings(), deps.discovery(), deps.refusals(),
                connection, deps.reconnectPrompt());
        this.panel = new UsersPanel(services, serverConfig.grantForms(), openOAuthClient, mode);
        this.chip = mode.comparesUsers() ? Optional.of(panel.scanAsChip()) : Optional.empty();
        this.connectionIdentityLine = panel.connectionIdentityLine();
        this.picker = mode.comparesUsers() ? Optional.of(panel.primaryUserPicker(openUsers)) : Optional.empty();
    }

    JComponent section() {
        return ScrollableForm.wrap(panel);
    }

    ScanAsChip chip() {
        return chip.orElseThrow();
    }

    ConnectionIdentityLine connectionIdentityLine() {
        return connectionIdentityLine;
    }

    Optional<PrimaryUserPicker> picker() {
        return picker;
    }

    CredentialPrompt credentialPrompt(CredentialPrompt.Actions actions) {
        return panel.credentialPrompt(actions);
    }

    ConnectedIdentity connectedAs(String identityId, AuthStrategy connectionAuth) {
        return new ConnectionFreshness(registry).snapshot(identityId, connectionAuth);
    }

    PrimaryUserCredentials primaryCredentials() {
        return credentialServices.primaryCredentials();
    }

    String primaryHint() {
        return mode.primaryRuns() + " run as the primary user, " + registry.primaryUser().name() + ".";
    }

    int refusedToolCalls() {
        return refusals.refusedCount();
    }

    void onChange(Runnable listener) {
        subscriptions.add(services.onChange(() -> SwingUtilities.invokeLater(listener)));
    }

    void refresh() {
        panel.refresh();
        chip.ifPresent(ScanAsChip::refresh);
        connectionIdentityLine.refresh();
        picker.ifPresent(PrimaryUserPicker::refresh);
    }

    void focusPrimaryCredentials() {
        panel.focusPrimaryCredentials();
    }

    void addStarter(IdentityRole role) {
        panel.addStarter(role);
    }

    String tabTitle() {
        return "Users (" + mode.shownUsers(registry.identities().size()) + ")" + (refusals.refusedCount() > 0 ? " ▲" : "");
    }

    void shutdown() {
        subscriptions.forEach(Runnable::run);
        panel.dispose();
        chip.ifPresent(ScanAsChip::dispose);
        connectionIdentityLine.dispose();
        picker.ifPresent(PrimaryUserPicker::dispose);
        credentialServices.close();
    }
}
