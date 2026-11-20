package com.mcpscanner.ui;

import com.mcpscanner.ui.state.ConnectionStatus;
import com.mcpscanner.ui.state.UiConnectionState;
import com.mcpscanner.ui.widgets.Blockers;
import com.mcpscanner.ui.widgets.PrimaryActionButton;

import java.util.Optional;

final class ConnectionStateRenderer {

    interface Host {
        UiConnectionState state();

        Optional<String> connectBlocker();
    }

    record Views(ConnectionHeader header, ScanBarView scanBar, ServerConfigPanel serverConfig,
                 InventoryPanels inventory, InventoryTabs inventoryTabs, OAuthClientSection oauthClient) {
    }

    private final Views views;
    private final Host host;

    ConnectionStateRenderer(Views views, Host host) {
        this.views = views;
        this.host = host;
    }

    void render() {
        views.scanBar().forgetPlannedCounts();
        UiConnectionState state = host.state();
        if (!(state instanceof UiConnectionState.Connected)) {
            views.inventory().serverInfo().clearConnection();
        }
        renderHeader(state);
        views.inventory().setAvailability(availability(state));
        refreshScanButton();
        refreshPrimaryReadiness();
        refreshChecksSummary();
        views.scanBar().refreshActivity();
    }

    void overlay(ConnectionStatus status) {
        views.header().statusCluster().update(status);
    }

    void refreshPrimaryReadiness() {
        PrimaryActionButton primary = views.header().connectButton();
        Blockers.apply(primary, idleConnectBlocker(), primaryTooltip(primary.getText()));
        refreshNextStepHint();
    }

    void refreshScanButton() {
        views.inventoryTabs().refreshCounts();
        views.inventory().refreshDetailActions();
        if (views.scanBar().refreshUnlessStarting()) {
            refreshNextStepHint();
        }
    }

    void refreshChecksSummary() {
        views.scanBar().refreshChecksSummary();
    }

    private void renderHeader(UiConnectionState state) {
        ConnectionStatus status = state.status();
        overlay(status);
        views.header().setConnectLabel(status.primaryButtonLabel());
        boolean connected = state instanceof UiConnectionState.Connected;
        views.header().connectButton().setPrimary(!connected);
        views.scanBar().showConnected(connected);
        applyConfigurationLock(state instanceof UiConnectionState.Connecting || connected);
    }

    private void applyConfigurationLock(boolean locked) {
        views.header().endpointField().setEnabled(!locked);
        views.header().transportCombo().setEnabled(!locked);
        views.serverConfig().setConfigurationLocked(locked);
        views.oauthClient().setLocked(locked);
        if (!locked) {
            views.serverConfig().revalidate();
            views.serverConfig().repaint();
        }
    }

    private void refreshNextStepHint() {
        views.header().showConnectHint(idleConnectBlocker().orElse(null));
        views.scanBar().refreshScanHint();
    }

    private Optional<String> idleConnectBlocker() {
        UiConnectionState state = host.state();
        boolean idle = !(state instanceof UiConnectionState.Connecting || state instanceof UiConnectionState.Connected);
        return idle ? connectBlocker() : Optional.empty();
    }

    private Optional<String> connectBlocker() {
        if (views.header().endpointField().getText().isBlank()) {
            return Optional.of("Enter the MCP endpoint URL");
        }
        return host.connectBlocker();
    }

    private static InventoryView.Availability availability(UiConnectionState state) {
        if (state instanceof UiConnectionState.Connected) {
            return InventoryView.Availability.CONNECTED;
        }
        if (state instanceof UiConnectionState.Failed) {
            return InventoryView.Availability.CONNECTION_FAILED;
        }
        if (state instanceof UiConnectionState.Connecting) {
            return InventoryView.Availability.CONNECTING;
        }
        return InventoryView.Availability.DISCONNECTED;
    }

    private static String primaryTooltip(String label) {
        return switch (label) {
            case "Disconnect" -> "Disconnect from the MCP server";
            case "Cancel" -> "Stop this connection attempt";
            default -> "Connect to the configured MCP server (Enter in the endpoint field)";
        };
    }
}
