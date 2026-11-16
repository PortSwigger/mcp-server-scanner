package com.mcpscanner.ui;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.identity.ConnectedIdentity;
import com.mcpscanner.identity.IdentityRole;
import com.mcpscanner.identity.MinedValueOriginGuard;
import com.mcpscanner.identity.credentials.CredentialOriginGuard;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.MinedArguments;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.scan.McpRepeaterRequestFactory;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.scan.ScanPlanner;
import com.mcpscanner.scan.ScanSession;
import com.mcpscanner.scan.request.RequestGenerator;
import com.mcpscanner.access.WriteReplayApproval;
import com.mcpscanner.ui.access.AccessApprovals;
import com.mcpscanner.ui.access.AccessPanel;
import com.mcpscanner.ui.access.AccessServices;
import com.mcpscanner.ui.access.IdentityShortcuts;
import com.mcpscanner.ui.completion.ValueCompletion;
import com.mcpscanner.ui.connect.PrimaryUserAuthSource;
import com.mcpscanner.identity.credentials.CredentialNeed;
import com.mcpscanner.ui.identities.CredentialPrompt;
import com.mcpscanner.ui.identities.IdentityConnection;
import com.mcpscanner.ui.connect.ConnectAttemptFactory;
import com.mcpscanner.ui.connect.ConnectCoordinator;
import com.mcpscanner.ui.connect.ConnectionAttemptResult;
import com.mcpscanner.ui.connect.ConnectionFailureHandler;
import com.mcpscanner.ui.scans.ScansPanel;
import com.mcpscanner.ui.scans.ScansServices;
import com.mcpscanner.ui.sendto.SendToDestination;
import com.mcpscanner.ui.sendto.SendToMenu;
import com.mcpscanner.ui.sendto.SendToShortcuts;
import com.mcpscanner.ui.serverinfo.ServerCardSource;
import com.mcpscanner.ui.state.ConnectAttempt;
import com.mcpscanner.ui.state.ConnectionStatus;
import com.mcpscanner.ui.state.UiAction;
import com.mcpscanner.ui.state.UiConnectionState;
import com.mcpscanner.ui.state.UiSideEffect;
import com.mcpscanner.ui.state.UiStateReducer;
import com.mcpscanner.ui.widgets.CopyableSecret;
import com.mcpscanner.ui.widgets.Edt;
import com.mcpscanner.ui.widgets.ScrollableForm;
import com.mcpscanner.ui.widgets.SideDrawer;
import com.mcpscanner.ui.widgets.TitledPanel;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.KeyboardFocusManager;
import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.time.Clock;

public class McpScannerTab extends JPanel {

    static final String CHECKS_SECTION = "Checks";
    static final String USERS_SECTION = "Users";
    static final String CLIENT_SECTION = "Client";
    static final String REQUESTS_SECTION = "Requests";
    static final String LOG_SECTION = "Log";
    static final String SETTINGS_SECTION = "Settings";
    static final String DISCONNECTING = "Disconnecting…";
    private static final Executor TOKEN_RENEWAL_EXECUTOR = task -> {
        Thread worker = new Thread(task, "mcp-token-refresh");
        worker.setDaemon(true);
        worker.start();
    };

    private final McpScannerTabDependencies deps;
    private final McpClientManager clientManager;
    private final ExtensionConfigStore configStore;
    private final McpEventLog eventLog;
    private final ServerConfigPanel serverConfigPanel;
    private final UiStateReducer reducer = new UiStateReducer();
    private final ConnectionFailureHandler connectionFailures =
            new ConnectionFailureHandler(SwingUtilities::invokeLater, this::onAuthTerminallyFailed);
    private final ConnectCoordinator connectCoordinator;
    private final PrimaryUserAuthSource connectAuth;
    private final ConnectAttemptFactory attemptFactory;
    private final ConnectionDescriber describer;
    private final AuthDiscoveryReports authDiscoveryReports;
    private final CredentialOriginGuard credentialOrigin;
    private final MinedValueOriginGuard minedValueOrigin;
    private final ScanLaunchPresenter scans;

    private final ConnectionHeader header = new ConnectionHeader();
    private final InventoryPanels inventory = new InventoryPanels();
    private final InventoryTabs inventoryTabs = new InventoryTabs();
    private final ScanActivityPanel scanActivity;
    private final ScanModeSelector scanModeSelector;
    private final ScanBar scanBar;
    private final ScanChecksPanel scanChecksPanel;
    private final AuthenticationOverview authenticationOverview;
    private final CredentialPromptPresenter credentialNeeds = new CredentialPromptPresenter();
    private final CredentialPrompt credentialPrompt;
    private final LoggerPanel loggerPanel;
    private final SettingsPanel settingsPanel;
    private final OAuthClientSection oauthClient;
    private final UsersView identities;
    private final SideDrawer drawer;
    private final ConnectionStateRenderer renderer;
    private final PendingReconnect pendingReconnect = new PendingReconnect(this::isDisconnected, this::requestConnect);
    private final DisconnectGate disconnects = new DisconnectGate(this::refreshAfterDisconnect);

    private final Consumer<McpEventLog.LogEntry> errorAlert = this::alertOnError;
    private final BiConsumer<String, Boolean> checksSummaryRefresh =
            (id, enabled) -> SwingUtilities.invokeLater(this::refreshChecksSummary);
    private final Consumer<ScanMode> scanModeRefresh = mode -> Edt.run(this::onScanModeChanged);
    private final Runnable requestFamilyRefresh = () -> Edt.run(this::replanScanButton);
    private final Runnable externalDisconnect = () -> SwingUtilities.invokeLater(this::onExternalDisconnect);
    private final Runnable stopGrantFieldsFollowingPrimary;

    private List<SendToDestination> sendToDestinations = List.of();
    private Optional<AccessPanel> accessPanel = Optional.empty();
    private Optional<ScansPanel> scansPanel = Optional.empty();
    private SendToShortcuts sendToShortcuts = SendToShortcuts.defaults();
    private UiConnectionState state = UiConnectionState.disconnected();
    private AuthStrategy connectionAuth;

    public McpScannerTab(McpScannerTabDependencies deps) {
        super(new BorderLayout());
        this.deps = Objects.requireNonNull(deps);
        this.clientManager = deps.clientManager();
        this.configStore = deps.configStore();
        this.eventLog = deps.eventLog();
        this.serverConfigPanel = deps.serverConfigPanel();
        this.credentialOrigin = CredentialOriginGuard.watching(deps.identities().registry(), eventLog,
                configStore::endpoint);
        this.minedValueOrigin = MinedValueOriginGuard.watching(deps.identities().registry(), eventLog,
                configStore::endpoint);
        this.connectCoordinator = new ConnectCoordinator(serverConfigPanel.oauthConfig(), clientManager, eventLog,
                deps.optionalGrants());
        this.describer = new ConnectionDescriber(serverConfigPanel.oauthConfig(), clientManager::scannerSession);
        this.authDiscoveryReports = new AuthDiscoveryReports(serverConfigPanel.oauthConfig()::lastDiscoveryFor);
        this.scans = new ScanLaunchPresenter(deps, new ScanPlanner(deps.generationSettings(),
                inventory::serverCapabilities, () -> clientManager.scannerSession().negotiatedProtocolVersion(),
                inventory::authorizationServer, deps.scanOwnerArguments()), this, new ScanHost());
        this.scanActivity = new ScanActivityPanel(deps.scanLauncher()::activity,
                deps.scanLauncher()::cancelRunningScans, deps.uiReads());
        this.oauthClient = new OAuthClientSection(serverConfigPanel, this::requestDisconnect);
        this.identities = new UsersView(deps.identities(),
                IdentityConnection.of(this::isConnected, this::isConnecting, this::reconnectAs,
                        this::connectedIdentity), deps.dialogOwner(), this, eventLog::warn, serverConfigPanel, this::openUsers,
                this::openOAuthClient);
        this.stopGrantFieldsFollowingPrimary = GrantFieldsFollowPrimary.watch(deps.identities().registry(),
                serverConfigPanel.grantForms());
        this.connectAuth = new PrimaryUserAuthSource(new ServerConfigAuthSource(serverConfigPanel),
                identities.primaryCredentials());
        this.credentialPrompt = identities.credentialPrompt(new PromptActions());
        this.attemptFactory = new ConnectAttemptFactory(connectAuth);
        this.scanModeSelector = new ScanModeSelector(deps.scanModeSetting());
        this.scanBar = new ScanBar(scanActivity, identities.chip(),
                SupportLinks.create(deps.logging()::logToError), scanModeSelector.button(),
                new PausedTasksNotice(deps.scanModeSetting()::current, deps.scanLauncher(), eventLog));
        this.scanChecksPanel = new ScanChecksPanel(deps.checkRegistry(), deps.checkSettings(),
                deps.logging()::logToError);
        this.authenticationOverview = createAuthenticationOverview();
        this.loggerPanel = new LoggerPanel(eventLog);
        this.settingsPanel = new SettingsPanel(configStore);
        this.drawer = new SideDrawer(inventoryTabs);
        this.renderer = new ConnectionStateRenderer(new ConnectionStateRenderer.Views(header, scanBar,
                serverConfigPanel, inventory, inventoryTabs, oauthClient, scanActivity),
                deps.checkRegistry(), deps.scanModeSetting()::current, new RenderHost());
        assemble();
    }

    private AuthenticationOverview createAuthenticationOverview() {
        TokenRenewal renewal = new TokenRenewal(TOKEN_RENEWAL_EXECUTOR,
                new TokenRenewalStatusReporter(eventLog, this::overlayStatus));
        Supplier<Clipboard> clipboard = () -> Toolkit.getDefaultToolkit().getSystemClipboard();
        return new AuthenticationOverview(Clock.systemDefaultZone(), new AccessTokenView(renewal, clipboard),
                new CopyableSecret("refresh token", clipboard), new ClientManagementView(clipboard));
    }

    public void shutdown() {
        deps.scanLauncher().cancelRunningScans();
        serverConfigPanel.shutdown();
        eventLog.unsubscribe(errorAlert);
        deps.checkSettings().removeListener(checksSummaryRefresh);
        deps.scanModeSetting().removeListener(scanModeRefresh);
        deps.generationSettings().removeFamilyListener(requestFamilyRefresh);
        clientManager.removeDisconnectListener(externalDisconnect);
        loggerPanel.dispose();
        scanChecksPanel.dispose();
        scanActivity.dispose();
        identities.shutdown();
        stopGrantFieldsFollowingPrimary.run();
        accessPanel.ifPresent(AccessPanel::dispose);
        scansPanel.ifPresent(ScansPanel::dispose);
    }

    public void setBurpSettingsOpener(Runnable openBurpSettings) {
        settingsPanel.offerBurpSettings(openBurpSettings);
    }

    public void setServerCardSource(ServerCardSource source) {
        inventory.serverInfo().useServerCards(source);
    }

    public void setSendToDestinations(List<SendToDestination> destinations) {
        this.sendToDestinations = List.copyOf(destinations);
    }

    public WriteReplayApproval writeReplayApproval() {
        return writeReplayApproval(new DestructiveScanGate(configStore, deps.destructiveScanPrompt()));
    }

    private WriteReplayApproval writeReplayApproval(DestructiveScanGate writeReplays) {
        return new WriteReplayApproval() {
            @Override
            public boolean approve(List<McpToolDefinition> tools) {
                return approve(tools, MinedArguments.NONE);
            }

            @Override
            public boolean approve(List<McpToolDefinition> tools, MinedArguments mined) {
                return writeReplays.confirm(McpScannerTab.this, tools, activeEndpoint(), mined);
            }
        };
    }

    public AccessPanel installAccess(AccessServices access) {
        scans.onWritesConfirmed(access.confirmations()::confirm);
        AccessPanel panel = new AccessPanel(access, new AccessApprovals(
                writeReplayApproval(DestructiveScanGate.forCheckAccess(configStore, deps.destructiveScanPrompt())),
                new MiningWriteConfirmation(deps.destructiveScanPrompt()::askLines, this)),
                this::repeater, eventLog::error);
        scans.gateLaunches(panel.mineFirst());
        panel.setIdentityShortcuts(new IdentitySectionShortcuts());
        accessPanel = Optional.of(installTitled(panel));
        return panel;
    }

    public void installScans(ScansServices services) {
        ScansPanel panel = new ScansPanel(services, deps.uiReads());
        scansPanel = Optional.of(installTitled(panel));
    }

    private <T extends JComponent & TitledPanel> T installTitled(T panel) {
        panel.onTitleChange(inventoryTabs::refreshCounts);
        inventoryTabs.addTitled(panel, panel::title);
        return panel;
    }

    private Optional<SendToDestination> repeater() {
        return sendToDestinations.stream().filter(destination -> "Repeater".equals(destination.name())).findFirst();
    }

    public void setSendToShortcuts(SendToShortcuts shortcuts) {
        this.sendToShortcuts = Objects.requireNonNull(shortcuts);
    }

    private void assemble() {
        configureInventory();
        seedFromConfig();
        serverConfigPanel.oauthConfig().setEndpointSupplier(() -> header.endpointField().getText().trim());
        configureDrawer();
        header.showConnectionIdentity(identities.connectionIdentityLine());
        header.showPrimaryPicker(identities.picker());
        header.showCredentialPrompt(credentialPrompt);
        add(header, BorderLayout.NORTH);
        add(drawer, BorderLayout.CENTER);
        add(scanBar, BorderLayout.SOUTH);
        wireHeader();
        wireSubscriptions();
        refreshIdentityIndicators();
        renderer.render();
    }

    private void configureInventory() {
        inventory.bindSendTo(new SendToMenu(() -> sendToDestinations, this::sendToUnavailableReason,
                deps.logging()::logToError, () -> sendToShortcuts), repeaterRequests());
        inventory.bindScans(scans.itemScanner(), deps.scanModeSetting()::current);
        inventory.bindCompletion(ValueCompletion.forClient(clientManager, this::isConnected, deps.dialogOwner()));
        inventory.tools().setSelectionPersistence(configStore, this::activeEndpoint);
        inventory.addTo(inventoryTabs);
    }

    private McpRepeaterRequestFactory repeaterRequests() {
        var session = clientManager.scannerSession();
        return new McpRepeaterRequestFactory(ScanSession.of(session::resolvedEndpoint, session::scannerHeaders),
                RequestGenerator.standard(), deps.requestRenderer(), deps.repeaterConnections());
    }

    private void configureDrawer() {
        drawer.addSection(CHECKS_SECTION, 'K', scanChecksPanel);
        drawer.addSection(USERS_SECTION, 'U', identities.section());
        drawer.addSection(CLIENT_SECTION, 'I', ScrollableForm.wrap(ClientTab.of(new ClientIdentityPanel(configStore),
                oauthClient)));
        drawer.addSection(REQUESTS_SECTION, 'R', new RequestFamiliesPanel(deps.generationSettings()));
        drawer.addSection(LOG_SECTION, 'L', loggerPanel);
        drawer.addSection(SETTINGS_SECTION, 'T', ScrollableForm.wrap(settingsPanel));
        drawer.expand(CHECKS_SECTION);
    }

    private void seedFromConfig() {
        Optional.ofNullable(configStore.endpoint()).ifPresent(header.endpointField()::setText);
        Optional.ofNullable(configStore.transport()).flatMap(McpScannerTab::transportNamed)
                .ifPresent(header.transportCombo()::setSelectedItem);
    }

    private static Optional<TransportType> transportNamed(String name) {
        try {
            return Optional.of(TransportType.valueOf(name));
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }

    private void wireHeader() {
        serverConfigPanel.setReadinessListener(this::onOAuthSettingsChanged);
        header.endpointField().getDocument().addDocumentListener(
                new EndpointEditListener(header.endpointField(), this::onEndpointEdited));
        header.endpointField().addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent event) {
                commitEndpointOrigin();
            }
        });
        header.transportCombo().addActionListener(e -> Optional.ofNullable(selectedTransport())
                .ifPresent(selected -> configStore.setTransport(selected.name())));
        header.connectButton().addActionListener(e -> onPrimary());
        scanBar.scanButton().addActionListener(e -> scans.scanSelection(inventory.selection()));
        scanBar.checksSummary().addActionListener(e -> drawer.expand(CHECKS_SECTION));
    }

    private void wireSubscriptions() {
        eventLog.subscribe(errorAlert);
        deps.checkSettings().addListener(checksSummaryRefresh);
        deps.scanModeSetting().addListener(scanModeRefresh);
        deps.generationSettings().addFamilyListener(requestFamilyRefresh);
        scans.onRequestsCounted(renderer::refreshScanButton);
        inventory.onSelectionChange(renderer::refreshScanButton);
        clientManager.addDisconnectListener(externalDisconnect);
        identities.onChange(this::refreshIdentityIndicators);
    }

    private void openUsers() {
        drawer.expand(USERS_SECTION);
    }

    private void openOAuthClient() {
        drawer.expand(CLIENT_SECTION);
        SwingUtilities.invokeLater(oauthClient::reveal);
    }

    private void onOAuthSettingsChanged() {
        renderer.refreshPrimaryReadiness();
        identities.refresh();
        refreshCredentialPrompt();
    }

    private void refreshIdentityIndicators() {
        renderer.refreshPrimaryReadiness();
        drawer.relabel(USERS_SECTION, identities.tabTitle());
        refreshPrimaryHint();
        refreshCredentialPrompt();
    }

    private void refreshPrimaryHint() {
        boolean idle = !(state instanceof UiConnectionState.Connected || state instanceof UiConnectionState.Connecting);
        header.showPrimaryHint(idle ? "Connect, discovery and Scan run as the primary user, "
                + identities.primaryName() + "." : null);
    }

    private void refreshCredentialPrompt() {
        credentialPrompt.show(credentialNeeds.need(state, connectAuth.connectNeed(), identities.refusedToolCalls()));
    }

    private TransportType selectedTransport() {
        return (TransportType) header.transportCombo().getSelectedItem();
    }

    private void onEndpointEdited(String endpoint, boolean hostChanged) {
        configStore.setEndpoint(endpoint);
        credentialNeeds.connectStarted();
        renderer.refreshPrimaryReadiness();
        if (hostChanged) {
            serverConfigPanel.oauthConfig().clearAutoDiscoveredOAuth();
        }
        serverConfigPanel.oauthConfig().onEndpointChanged();
        renderer.refreshScanButton();
    }

    private void refreshChecksSummary() {
        renderer.refreshChecksSummary();
    }

    private void replanScanButton() {
        scans.forgetPlannedCounts();
        renderer.refreshScanButton();
    }

    private void onScanModeChanged() {
        scanModeSelector.refresh();
        renderer.refreshScanButton();
        renderer.refreshChecksSummary();
    }

    private void alertOnError(McpEventLog.LogEntry entry) {
        if (entry.level() == McpEventLog.Level.ERROR) {
            SwingUtilities.invokeLater(() -> drawer.alert(LOG_SECTION, "New errors were logged"));
        }
    }

    private void onPrimary() {
        if (disconnects.isDisconnecting()) {
            return;
        }
        pendingReconnect.discard();
        if (state instanceof UiConnectionState.Connecting) {
            eventLog.info("Connection attempt cancelled");
        }
        if (state instanceof UiConnectionState.Connecting || state instanceof UiConnectionState.Connected) {
            dispatch(UiAction.DisconnectRequested.INSTANCE);
            return;
        }
        requestConnect();
    }

    private void commitEndpointOrigin() {
        minedValueOrigin.commit(header.endpointField().getText());
        credentialOrigin.commit(header.endpointField().getText())
                .ifPresent(cleared -> overlayStatus(ConnectionStatus.credentialsCleared(cleared.message())));
    }

    private void requestConnect() {
        commitEndpointOrigin();
        dispatch(attemptFactory.attemptFor(header.endpointField().getText(), selectedTransport(),
                connectAuth.authType()));
    }

    private void reconnectAs(Runnable switchUser) {
        deps.scanLauncher().cancelRunningScans();
        switchUser.run();
        reconnect();
    }

    private void reconnect() {
        Runnable connectAgain = pendingReconnect.request();
        if (!isDisconnected()) {
            dispatch(UiAction.DisconnectRequested.INSTANCE);
        }
        disconnects.whenIdle(connectAgain);
    }

    private void refreshAfterDisconnect() {
        renderer.refreshPrimaryReadiness();
    }

    private void requestDisconnect() {
        if (state instanceof UiConnectionState.Connected) {
            dispatch(UiAction.DisconnectRequested.INSTANCE);
        }
    }

    private void onExternalDisconnect() {
        if (state instanceof UiConnectionState.Connected) {
            eventLog.warn(McpClientManager.CONNECTION_LOST);
        }
        dispatch(UiAction.ExternalDisconnect.INSTANCE);
    }

    private void onAuthTerminallyFailed() {
        requireEdt();
        deps.scanLauncher().cancelRunningScans();
        eventLog.error("OAuth token refresh was rejected; the connection was closed");
        identities.primaryCredentials().sessionRejected();
        dispatch(UiAction.AuthTerminallyFailed.INSTANCE);
    }

    private static void requireEdt() {
        if (!SwingUtilities.isEventDispatchThread()) {
            throw new IllegalStateException("Must be called on the Event Dispatch Thread");
        }
    }

    private void dispatch(UiAction action) {
        requireEdt();
        boolean focusInside = focusIsInside();
        UiConnectionState previous = state;
        UiStateReducer.Reduction reduction = reducer.reduce(state, action);
        this.state = reduction.state();
        reduction.sideEffects().forEach(this::apply);
        renderer.render();
        identities.refresh();
        refreshPrimaryHint();
        refreshCredentialPrompt();
        if (focusInside && state.getClass() != previous.getClass()) {
            focusTargetForState().requestFocusInWindow();
        }
    }

    private JComponent focusTargetForState() {
        if (state instanceof UiConnectionState.Connected) {
            return inventory.focusTable();
        }
        if (state instanceof UiConnectionState.Connecting) {
            return header.connectButton();
        }
        return header.endpointField();
    }

    private boolean focusIsInside() {
        Component owner = KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();
        return owner != null && SwingUtilities.isDescendingFrom(owner, this);
    }

    private void apply(UiSideEffect effect) {
        applyConnectionEffect(effect);
        applyPanelEffect(effect);
    }

    private void applyConnectionEffect(UiSideEffect effect) {
        if (effect instanceof UiSideEffect.SpawnConnectWorker spawn) {
            spawnConnectWorker(spawn.attempt());
        } else if (effect instanceof UiSideEffect.CancelConnect cancel) {
            cancel.cancellable().cancel();
        } else if (effect instanceof UiSideEffect.RunDisconnect) {
            new DisconnectWorker(clientManager, deps.logging()::logToError,
                    disconnects.begin()).execute();
        } else if (effect instanceof UiSideEffect.ReleaseConnectionAuth) {
            releaseConnectionAuth();
        } else if (effect instanceof UiSideEffect.RetireConnection) {
            connectionFailures.retireConnection();
        } else if (effect instanceof UiSideEffect.LogWarning warning) {
            eventLog.warn(warning.message());
        }
    }

    private void applyPanelEffect(UiSideEffect effect) {
        if (effect instanceof UiSideEffect.PublishOAuthStrategy publish) {
            serverConfigPanel.oauthConfig().publishOauthStrategy(publish.strategy());
        } else if (effect instanceof UiSideEffect.ClearOAuthStrategy) {
            serverConfigPanel.clearEstablishedAuth();
        } else if (effect instanceof UiSideEffect.ClearAutoDiscoveredOAuthFields) {
            serverConfigPanel.oauthConfig().clearAutoDiscoveredOAuth();
        } else if (effect instanceof UiSideEffect.PopulateInventory populate) {
            inventory.populate(populate.result());
        } else if (effect instanceof UiSideEffect.ClearInventory) {
            inventory.clear();
        }
    }

    private void releaseConnectionAuth() {
        connectionAuth = null;
        deps.authHolder().clear();
    }

    private void spawnConnectWorker(ConnectAttempt attempt) {
        deps.identities().refusals().clear();
        credentialNeeds.connectStarted();
        ConnectWorker worker = new ConnectWorker(connectCoordinator, attempt,
                connectionFailures.beginConnection(), new ConnectHost());
        dispatch(new UiAction.ConnectWorkerAttached(worker.cancellable()));
        worker.execute();
    }

    private void onConnected(ConnectAttempt attempt, ConnectionAttemptResult outcome) {
        if (attempt.isOptionalGrant()) {
            serverConfigPanel.clearGrantSecrets();
        }
        ConnectionStatus status = describer.status(attempt, outcome);
        connectionAuth = Objects.requireNonNull(outcome.resolvedAuth());
        deps.authHolder().set(connectionAuth);
        recordConnectedUser(attempt, outcome);
        dispatch(new UiAction.ConnectSucceeded(outcome.result(), attempt.host(), status, outcome.oauthStrategy(),
                identities.connectedAs(attempt.identityId(), connectionAuth)));
        inventory.advertise(outcome.authorizationServer());
        replanScanButton();
        if (state instanceof UiConnectionState.Connected connected) {
            ConnectionSummary connection = describer.summary(attempt, outcome);
            inventory.showConnection(connection);
            inventory.serverInfo().showAuthDiscovery(authDiscoveryReports.after(attempt.endpoint(), connectionAuth));
            authenticationOverview.show(AuthenticationSummaryFactory.from(attempt, outcome, connected.connectedAs().name(),
                    serverConfigPanel.oauthConfig()::registrationFor));
            inventory.serverInfo().showAuthentication(authenticationOverview);
        }
    }

    private void recordConnectedUser(ConnectAttempt attempt, ConnectionAttemptResult outcome) {
        if (outcome.oauthStrategy() != null) {
            identities.primaryCredentials().signedIn(attempt.identityId(), outcome.oauthStrategy());
        } else if (outcome.autoResolutionLabel().isPresent()) {
            identities.primaryCredentials().detectedNoAuthentication(attempt.identityId());
        }
    }

    private void onCredentialsNeeded(String reason, CredentialNeed need) {
        if (!connectAuth.isOptionalGrantSelected()) {
            credentialNeeds.connectFailed(need);
        }
        onConnectFailed(reason);
    }

    private void onConnectFailed(String reason) {
        deps.logging().logToError("Connection failed: " + reason);
        eventLog.error("Connection failed: " + reason);
        dispatch(new UiAction.ConnectFailed(reason));
    }

    private void offerToTurnOffBurpNetworking() {
        if (deps.burpNetworkingPrompt().offerToTurnOff(this)) {
            configStore.setUseBurpNetworking(false);
            onPrimary();
        }
    }

    private Optional<String> sendToUnavailableReason() {
        if (sendToDestinations.isEmpty()) {
            return Optional.of("No Burp destinations are available");
        }
        return isConnected() ? Optional.empty() : Optional.of("Connect to an MCP server first");
    }

    private Optional<ConnectedIdentity> connectedIdentity() {
        return state instanceof UiConnectionState.Connected connected
                ? Optional.of(connected.connectedAs()) : Optional.empty();
    }

    private boolean isDisconnected() {
        return state instanceof UiConnectionState.Disconnected;
    }

    private boolean isConnecting() {
        return state instanceof UiConnectionState.Connecting;
    }

    private boolean isConnected() {
        return state instanceof UiConnectionState.Connected && clientManager.isConnected();
    }

    private String activeEndpoint() {
        return clientManager.isConnected() ? clientManager.scannerSession().resolvedEndpoint() : null;
    }

    private void overlayStatus(ConnectionStatus status) {
        renderer.overlay(status);
    }

    private AuthStrategy requireConnectionAuth() {
        if (connectionAuth == null) {
            throw new IllegalStateException("Connect before scanning");
        }
        return connectionAuth;
    }

    private final class ConnectHost implements ConnectWorker.Host {
        @Override
        public boolean isCurrent(ConnectAttempt attempt) {
            return state instanceof UiConnectionState.Connecting connecting && connecting.attempt() == attempt;
        }

        @Override
        public void dispatch(UiAction action) {
            McpScannerTab.this.dispatch(action);
        }

        @Override
        public void connected(ConnectAttempt attempt, ConnectionAttemptResult outcome) {
            onConnected(attempt, outcome);
        }

        @Override
        public void connectFailed(String reason) {
            onConnectFailed(reason);
        }

        @Override
        public void credentialsNeeded(String reason, CredentialNeed need) {
            onCredentialsNeeded(reason, need);
        }

        @Override
        public void burpRefusedStreamedReply(String reason) {
            onConnectFailed(reason);
            offerToTurnOffBurpNetworking();
        }
    }

    private final class ScanHost implements ScanLaunchPresenter.Host {
        @Override
        public UiConnectionState state() {
            return state;
        }

        @Override
        public AuthStrategy connectionAuth() {
            return requireConnectionAuth();
        }

        @Override
        public boolean isConnected() {
            return McpScannerTab.this.isConnected();
        }

        @Override
        public void showStatus(ConnectionStatus status) {
            overlayStatus(status);
        }

        @Override
        public void scanStarting() {
            renderer.showScanStarting();
        }

        @Override
        public void scanSettled() {
            renderer.refreshScanButton();
            scanActivity.refresh();
        }
    }

    private final class RenderHost implements ConnectionStateRenderer.Host {
        @Override
        public UiConnectionState state() {
            return state;
        }

        @Override
        public boolean isConnected() {
            return McpScannerTab.this.isConnected();
        }

        @Override
        public boolean scanInFlight() {
            return scans.inFlight();
        }

        @Override
        public Optional<String> connectBlocker() {
            if (disconnects.isDisconnecting()) {
                return Optional.of(DISCONNECTING);
            }
            return connectAuth.connectBlocker();
        }

        @Override
        public Optional<PlannedRequests> plannedRequests(ScanInventory selection) {
            return scans.plannedRequests(selection);
        }

        @Override
        public void forgetPlannedCounts() {
            scans.forgetPlannedCounts();
        }
    }

    private final class PromptActions implements CredentialPrompt.Actions {
        @Override
        public void connect() {
            if (disconnects.isDisconnecting()) {
                reconnect();
            } else {
                onPrimary();
            }
        }

        @Override
        public void openOAuthClient() {
            McpScannerTab.this.openOAuthClient();
        }

        @Override
        public void openPrimaryUser() {
            openUsers();
            SwingUtilities.invokeLater(identities::focusPrimaryCredentials);
        }
    }

    private final class IdentitySectionShortcuts implements IdentityShortcuts {
        @Override
        public void addPeer() {
            addStarter(IdentityRole.PEER);
        }

        @Override
        public void addLowerPrivilegeUser() {
            addStarter(IdentityRole.LOWER);
        }

        @Override
        public void openIdentities() {
            openUsers();
        }

        private void addStarter(IdentityRole role) {
            identities.addStarter(role);
            openIdentities();
        }
    }
}
