package com.mcpscanner.ui;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.scan.ScanPlanner;
import com.mcpscanner.ui.access.LaunchGate;
import com.mcpscanner.ui.state.ConnectionStatus;
import com.mcpscanner.ui.state.UiConnectionState;
import com.mcpscanner.ui.widgets.Edt;
import com.mcpscanner.ui.widgets.SideDrawer;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.util.List;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

final class ScanSection implements ScanFeature {

    interface Host extends ScanBarRenderer.Host {
        AuthStrategy connectionAuth();

        void showStatus(ConnectionStatus status);

        void refreshScanButton();
    }

    private final ScanServices services;
    private final InventoryPanels inventory;
    private final Host host;
    private final ScanLaunchPresenter scans;
    private final ScanActivityPanel scanActivity;
    private final ScanModeSelector scanModeSelector;
    private final ScanBar scanBar;
    private final ScanChecksPanel scanChecksPanel;
    private final ScanBarRenderer view;

    private final BiConsumer<String, Boolean> checksSummaryRefresh =
            (id, enabled) -> SwingUtilities.invokeLater(this::refreshChecksSummary);
    private final Consumer<ScanMode> scanModeRefresh = mode -> Edt.run(this::onScanModeChanged);
    private final Runnable requestFamilyRefresh = () -> Edt.run(this::replanScanButton);

    ScanSection(McpScannerTabDependencies deps, ScanServices services, InventoryPanels inventory,
                Component parent, JComponent compareChip, Host host) {
        this.services = services;
        this.inventory = inventory;
        this.host = host;
        this.scans = new ScanLaunchPresenter(deps, services, new ScanPlanner(services.generationSettings(),
                inventory::serverCapabilities,
                () -> deps.clientManager().scannerSession().negotiatedProtocolVersion(),
                inventory::authorizationServer, services.scanOwnerArguments()), parent, new PresenterHost());
        this.scanActivity = new ScanActivityPanel(services.scanLauncher()::activity,
                services.scanLauncher()::cancelRunningScans, deps.uiReads());
        this.scanModeSelector = new ScanModeSelector(services.scanModeSetting());
        this.scanBar = new ScanBar(scanActivity, compareChip,
                SupportLinks.create(deps.logging()::logToError), scanModeSelector.button(),
                new PausedTasksNotice(services.scanModeSetting()::current, services.scanLauncher(), deps.eventLog()));
        this.scanChecksPanel = new ScanChecksPanel(services.checkRegistry(), services.checkSettings(),
                deps.logging()::logToError);
        this.view = new ScanBarRenderer(scanBar, scanActivity, inventory, scans, services.checkRegistry(),
                services.scanModeSetting()::current, host);
        wire();
    }

    private void wire() {
        scanBar.scanButton().addActionListener(e -> scans.scanSelection(inventory.selection()));
        services.checkSettings().addListener(checksSummaryRefresh);
        services.scanModeSetting().addListener(scanModeRefresh);
        services.generationSettings().addFamilyListener(requestFamilyRefresh);
        scans.onRequestsCounted(host::refreshScanButton);
    }

    void onWritesConfirmed(Consumer<List<McpToolDefinition>> listener) {
        scans.onWritesConfirmed(listener);
    }

    void gateLaunches(LaunchGate gate) {
        scans.gateLaunches(gate);
    }

    @Override
    public JComponent bar() {
        return scanBar;
    }

    @Override
    public ScanBarView view() {
        return view;
    }

    @Override
    public void addChecksSection(SideDrawer drawer) {
        drawer.addSection(McpScannerTab.CHECKS_SECTION, 'K', checksWithSignedInConsent());
        scanBar.checksSummary().addActionListener(e -> drawer.expand(McpScannerTab.CHECKS_SECTION));
    }

    private JComponent checksWithSignedInConsent() {
        JPanel checks = new JPanel(new BorderLayout());
        checks.add(scanChecksPanel, BorderLayout.CENTER);
        checks.add(new SignedInConsentOption(services.signedInConsent()), BorderLayout.SOUTH);
        return checks;
    }

    @Override
    public void addRequestsSection(SideDrawer drawer) {
        drawer.addSection(McpScannerTab.REQUESTS_SECTION, 'R', new RequestFamiliesPanel(services.generationSettings()));
    }

    @Override
    public void openDefaultSection(SideDrawer drawer) {
        drawer.expand(McpScannerTab.CHECKS_SECTION);
    }

    @Override
    public void bindInventory() {
        inventory.bindScans(scans.itemScanner(), services.scanModeSetting()::current);
    }

    @Override
    public void cancelRunningScans() {
        services.scanLauncher().cancelRunningScans();
    }

    @Override
    public void shutdown() {
        services.checkSettings().removeListener(checksSummaryRefresh);
        services.scanModeSetting().removeListener(scanModeRefresh);
        services.generationSettings().removeFamilyListener(requestFamilyRefresh);
        scanChecksPanel.dispose();
        scanActivity.dispose();
    }

    private void refreshChecksSummary() {
        view.refreshChecksSummary();
    }

    private void replanScanButton() {
        scans.forgetPlannedCounts();
        host.refreshScanButton();
    }

    private void onScanModeChanged() {
        scanModeSelector.refresh();
        host.refreshScanButton();
        view.refreshChecksSummary();
    }

    private final class PresenterHost implements ScanLaunchPresenter.Host {
        @Override
        public UiConnectionState state() {
            return host.state();
        }

        @Override
        public AuthStrategy connectionAuth() {
            return host.connectionAuth();
        }

        @Override
        public boolean isConnected() {
            return host.isConnected();
        }

        @Override
        public void showStatus(ConnectionStatus status) {
            host.showStatus(status);
        }

        @Override
        public void scanStarting() {
            inventory.refreshDetailActions();
            view.showStarting();
        }

        @Override
        public void scanSettled() {
            host.refreshScanButton();
            scanActivity.refresh();
        }
    }
}
