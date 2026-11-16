package com.mcpscanner.ui;

import com.mcpscanner.checks.registry.ScanCheckRegistry;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.ui.state.ConnectionStatus;
import com.mcpscanner.ui.state.UiConnectionState;
import com.mcpscanner.ui.widgets.Blockers;
import com.mcpscanner.ui.widgets.PrimaryActionButton;

import java.util.Optional;
import java.util.function.Supplier;

final class ConnectionStateRenderer {

    interface Host {
        UiConnectionState state();

        boolean isConnected();

        boolean scanInFlight();

        Optional<String> connectBlocker();

        Optional<PlannedRequests> plannedRequests(ScanInventory selection);

        void forgetPlannedCounts();
    }

    record Views(ConnectionHeader header, ScanBar scanBar, ServerConfigPanel serverConfig,
                 InventoryPanels inventory, InventoryTabs inventoryTabs,
                 OAuthClientSection oauthClient, ScanActivityPanel scanActivity) {
    }

    private final Views views;
    private final ScanCheckRegistry checkRegistry;
    private final Supplier<ScanMode> scanMode;
    private final Host host;

    ConnectionStateRenderer(Views views, ScanCheckRegistry checkRegistry, Supplier<ScanMode> scanMode, Host host) {
        this.views = views;
        this.checkRegistry = checkRegistry;
        this.scanMode = scanMode;
        this.host = host;
    }

    void render() {
        host.forgetPlannedCounts();
        UiConnectionState state = host.state();
        if (!(state instanceof UiConnectionState.Connected)) {
            views.inventory().serverInfo().clearConnection();
        }
        renderHeader(state);
        views.inventory().setAvailability(availability(state));
        refreshScanButton();
        refreshPrimaryReadiness();
        refreshChecksSummary();
        views.scanActivity().refresh();
    }

    void overlay(ConnectionStatus status) {
        views.header().statusCluster().update(status);
    }

    void showScanStarting() {
        views.inventory().refreshDetailActions();
        scanButton().setEnabled(false);
        scanButton().setText(ScanLaunchPresenter.STARTING);
    }

    void refreshPrimaryReadiness() {
        PrimaryActionButton primary = views.header().connectButton();
        Blockers.apply(primary, idleConnectBlocker(), primaryTooltip(primary.getText()));
        refreshNextStepHint();
    }

    void refreshScanButton() {
        views.inventoryTabs().refreshCounts();
        views.inventory().refreshDetailActions();
        views.scanBar().refreshPausedTasks();
        if (host.scanInFlight()) {
            return;
        }
        ScanReadiness readiness = scanReadiness();
        Blockers.apply(scanButton(), readiness.blocker(), readiness.tooltip(scanMode.get()));
        scanButton().setText(readiness.buttonLabel());
        refreshNextStepHint();
    }

    void refreshChecksSummary() {
        long enabled = checkRegistry.enabledActiveCheckCount();
        views.scanBar().checksSummary().setText(enabled + " MCP checks on");
        views.scanBar().checksSummary().setToolTipText(
                "Scans run " + ScanModeText.of(scanMode.get()).checksRun(enabled) + ". Click to review them.");
    }

    private void renderHeader(UiConnectionState state) {
        ConnectionStatus status = state.status();
        overlay(status);
        views.header().setConnectLabel(status.primaryButtonLabel());
        boolean connected = state instanceof UiConnectionState.Connected;
        views.header().connectButton().setPrimary(!connected);
        scanButton().setPrimary(connected);
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
        UiConnectionState state = host.state();
        boolean nothingToTick = state instanceof UiConnectionState.Connecting
                || (host.isConnected() && views.inventory().isEmpty());
        views.scanBar().showScanHint(nothingToTick ? null : scanReadiness().shortBlocker().orElse(null));
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

    private ScanReadiness scanReadiness() {
        ScanInventory selection = views.inventory().selection();
        Optional<PlannedRequests> requests = host.isConnected() ? host.plannedRequests(selection) : Optional.empty();
        return new ScanReadiness(host.isConnected(), selection, requests);
    }

    private PrimaryActionButton scanButton() {
        return views.scanBar().scanButton();
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
