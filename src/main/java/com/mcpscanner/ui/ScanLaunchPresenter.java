package com.mcpscanner.ui;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.CredentialedHeaders;
import com.mcpscanner.scan.OutcomeReportingScan;
import com.mcpscanner.scan.RunningScan;
import com.mcpscanner.scan.ScanConnection;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.scan.ScanOutcome;
import com.mcpscanner.scan.ScanPlanner;
import com.mcpscanner.scan.ScanTarget;
import com.mcpscanner.scan.request.GeneratedScan;
import com.mcpscanner.ui.access.LaunchGate;
import com.mcpscanner.ui.state.ConnectionStatus;
import com.mcpscanner.ui.state.UiConnectionState;
import com.mcpscanner.ui.widgets.Edt;

import javax.swing.SwingWorker;
import java.awt.Component;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Supplier;

final class ScanLaunchPresenter {

    static final String STARTING = "Starting scan…";

    interface Host {
        UiConnectionState state();

        AuthStrategy connectionAuth();

        boolean isConnected();

        void showStatus(ConnectionStatus status);

        void scanStarting();

        void scanSettled();
    }

    private final McpScannerTabDependencies deps;
    private final ScanPlanner planner;
    private final Component parent;
    private final Host host;
    private final DestructiveScanGate destructiveScans;
    private final PlannedRequestCounts<PlannedRequests> plannedCounts;
    private Consumer<List<McpToolDefinition>> confirmedWrites = tools -> { };
    private LaunchGate launchGate = LaunchGate.DIRECT;
    private boolean inFlight;
    private RunningScan latest;

    ScanLaunchPresenter(McpScannerTabDependencies deps, ScanPlanner planner, Component parent, Host host) {
        this.deps = deps;
        this.planner = planner;
        this.parent = parent;
        this.host = host;
        this.destructiveScans = new DestructiveScanGate(deps.configStore(), deps.destructiveScanPrompt(),
                () -> ScanModeText.of(deps.scanModeSetting().current()).invoker());
        this.plannedCounts = new PlannedRequestCounts<>(deps.uiReads());
    }

    void onRequestsCounted(Runnable listener) {
        plannedCounts.onCounted(listener);
    }

    void forgetPlannedCounts() {
        plannedCounts.invalidate();
    }

    void onWritesConfirmed(Consumer<List<McpToolDefinition>> listener) {
        confirmedWrites = listener;
    }

    void gateLaunches(LaunchGate gate) {
        launchGate = gate;
    }

    boolean inFlight() {
        return inFlight;
    }

    InventoryScanner itemScanner() {
        return new ItemScanner();
    }

    Optional<PlannedRequests> plannedRequests(ScanInventory selection) {
        return plannedCounts.count(selection, () -> PlannedRequests.of(planner.planSelection(selection)));
    }

    void scanSelection(ScanInventory selection) {
        launchGate.run(() -> launchSelection(selection));
    }

    private void launchSelection(ScanInventory selection) {
        GeneratedScan scan = planner.planSelection(selection);
        if (scan.messages().isEmpty()) {
            deps.logging().logToError("Scan skipped: nothing to send");
            return;
        }
        launch(scan, new ScanReadiness(true, selection, PlannedRequests.of(scan)).summary());
    }

    private void launch(GeneratedScan scan, String summary) {
        ScanMode mode = deps.scanModeSetting().current();
        ScanConnection connection = deps.scanLauncher().captureConnection();
        AuthStrategy strategy = host.connectionAuth();
        String endpoint = deps.clientManager().scannerSession().resolvedEndpoint();
        Supplier<RunningScan> started = deps.scanLauncher().captureScan(mode, endpoint, scan,
                CredentialedHeaders.of(deps.clientManager().scannerSession()::scannerHeaders, strategy), connection);
        if (!confirmDestructiveScan(scan.invokedTools(), endpoint)) {
            return;
        }
        deps.authHolder().set(strategy);
        deps.eventLog().kept(startedMessage(summary, mode));
        inFlight = true;
        host.scanStarting();
        new ScanStartWorker(started, summary, mode, host.state()).execute();
    }

    private String startedMessage(String summary, ScanMode mode) {
        return "Scan started: " + summary + " with "
                + ScanModeText.of(mode).checksRun(deps.checkRegistry().enabledActiveCheckCount());
    }

    private boolean confirmDestructiveScan(List<McpToolDefinition> selectedTools, String endpoint) {
        if (endpoint == null || endpoint.isEmpty()) {
            deps.logging().logToError(
                    "Scan blocked: no resolved endpoint to scope destructive-scan confirmation against");
            return false;
        }
        if (!destructiveScans.confirm(parent, selectedTools, endpoint, planner.minedArguments(selectedTools))) {
            deps.eventLog().kept("Scan cancelled at the unsafe-tool confirmation");
            host.showStatus(ConnectionStatus.scanCancelled());
            return false;
        }
        confirmedWrites.accept(DestructiveScanPolicy.nonReadOnly(selectedTools));
        return true;
    }

    private final class ItemScanner implements InventoryScanner {
        @Override
        public Optional<String> blocker(ScanTarget target) {
            if (inFlight) {
                return Optional.of(STARTING);
            }
            return new ScanReadiness(host.isConnected(), target.inventory(), plannedCount(target)).blocker();
        }

        private Optional<PlannedRequests> plannedCount(ScanTarget target) {
            if (!host.isConnected()) {
                return Optional.empty();
            }
            return plannedCounts.count(target, () -> PlannedRequests.of(planner.planItem(target)));
        }

        @Override
        public void scan(ScanTarget target) {
            launchGate.run(() -> launch(planner.planItem(target), ScanReadiness.describe(target.inventory())));
        }
    }

    private final class ScanStartWorker extends SwingWorker<RunningScan, Void> {
        private final Supplier<RunningScan> scan;
        private final String summary;
        private final ScanMode mode;
        private final UiConnectionState startedIn;

        ScanStartWorker(Supplier<RunningScan> scan, String summary, ScanMode mode, UiConnectionState startedIn) {
            this.scan = scan;
            this.summary = summary;
            this.mode = mode;
            this.startedIn = startedIn;
        }

        @Override
        protected RunningScan doInBackground() {
            return scan.get();
        }

        @Override
        protected void done() {
            inFlight = false;
            host.scanSettled();
            if (host.state() == startedIn) {
                reportOutcome();
            }
        }

        private void reportOutcome() {
            try {
                RunningScan running = get();
                deps.logging().logToOutput("Scan started for " + summary);
                host.showStatus(startedStatus());
                watch(running);
            } catch (Exception ex) {
                String reason = Failures.reason(ex);
                deps.logging().logToError("Scan failed: " + reason);
                deps.eventLog().error("Scan failed: " + reason);
                host.showStatus(ConnectionStatus.scanFailed(reason));
            }
        }

        private void watch(RunningScan running) {
            latest = running;
            if (running instanceof OutcomeReportingScan reporting) {
                reporting.whenCompleted(outcome -> Edt.run(() -> reportEnded(running, outcome)));
            }
        }

        private void reportEnded(RunningScan running, ScanOutcome outcome) {
            if (running == latest && host.state() == startedIn) {
                host.showStatus(ConnectionStatus.scanEnded(outcome, ScanModeText.of(mode).issuesLocation()));
            }
        }

        private ConnectionStatus startedStatus() {
            if (deps.scanLauncher().waitsForPausedTasks(mode)) {
                return ConnectionStatus.scanWaitingForPausedTasks(summary);
            }
            return ConnectionStatus.scanStarted(summary, ScanModeText.of(mode).resultsLocation());
        }
    }
}
