package com.mcpscanner.ui;

import com.mcpscanner.checks.registry.ScanCheckRegistry;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.ui.state.UiConnectionState;
import com.mcpscanner.ui.widgets.Blockers;
import com.mcpscanner.ui.widgets.PrimaryActionButton;

import java.util.Optional;
import java.util.function.Supplier;

final class ScanBarRenderer implements ScanBarView {

    interface Host {
        UiConnectionState state();

        boolean isConnected();
    }

    private final ScanBar scanBar;
    private final ScanActivityPanel scanActivity;
    private final InventoryPanels inventory;
    private final ScanLaunchPresenter scans;
    private final ScanCheckRegistry checkRegistry;
    private final Supplier<ScanMode> scanMode;
    private final Host host;

    ScanBarRenderer(ScanBar scanBar, ScanActivityPanel scanActivity, InventoryPanels inventory,
                    ScanLaunchPresenter scans, ScanCheckRegistry checkRegistry, Supplier<ScanMode> scanMode,
                    Host host) {
        this.scanBar = scanBar;
        this.scanActivity = scanActivity;
        this.inventory = inventory;
        this.scans = scans;
        this.checkRegistry = checkRegistry;
        this.scanMode = scanMode;
        this.host = host;
    }

    @Override
    public void forgetPlannedCounts() {
        scans.forgetPlannedCounts();
    }

    @Override
    public boolean refreshUnlessStarting() {
        scanBar.refreshPausedTasks();
        if (scans.inFlight()) {
            return false;
        }
        ScanReadiness readiness = scanReadiness();
        Blockers.apply(scanButton(), readiness.blocker(), readiness.tooltip(scanMode.get()));
        scanButton().setText(readiness.buttonLabel());
        return true;
    }

    @Override
    public void refreshScanHint() {
        UiConnectionState state = host.state();
        boolean nothingToTick = state instanceof UiConnectionState.Connecting
                || (host.isConnected() && inventory.isEmpty());
        scanBar.showScanHint(nothingToTick ? null : scanReadiness().shortBlocker().orElse(null));
    }

    @Override
    public void refreshChecksSummary() {
        long enabled = checkRegistry.enabledActiveCheckCount();
        scanBar.checksSummary().setText(enabled + " MCP checks on");
        scanBar.checksSummary().setToolTipText(
                "Scans run " + ScanModeText.of(scanMode.get()).checksRun(enabled) + ". Click to review them.");
    }

    @Override
    public void refreshActivity() {
        scanActivity.refresh();
    }

    @Override
    public void showConnected(boolean connected) {
        scanButton().setPrimary(connected);
    }

    @Override
    public void showStarting() {
        scanButton().setEnabled(false);
        scanButton().setText(ScanLaunchPresenter.STARTING);
    }

    private ScanReadiness scanReadiness() {
        ScanInventory selection = inventory.selection();
        Optional<PlannedRequests> requests = host.isConnected() ? scans.plannedRequests(selection) : Optional.empty();
        return new ScanReadiness(host.isConnected(), selection, requests);
    }

    private PrimaryActionButton scanButton() {
        return scanBar.scanButton();
    }
}
