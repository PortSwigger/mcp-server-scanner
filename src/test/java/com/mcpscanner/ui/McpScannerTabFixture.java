package com.mcpscanner.ui;

import com.mcpscanner.testutil.ManualReadScheduler;
import com.mcpscanner.config.AuthTypeNames;
import com.mcpscanner.ui.identities.ReconnectPrompt;
import com.mcpscanner.testutil.PlainFraming;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.identity.Identity;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.IdentityStore;
import com.mcpscanner.identity.ToolCallRefusals;
import com.mcpscanner.identity.credentials.IdentityCredentialServices;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.identity.credentials.ScopeApprovals;
import com.mcpscanner.identity.discovery.ComparedDiscovery;
import com.mcpscanner.identity.discovery.IdentityListings;
import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.auth.grants.OptionalGrantSettings;
import com.mcpscanner.identity.credentials.SharedAuthSettings;
import com.mcpscanner.checks.registry.ScanCheckRegistry;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.mcp.ToolAnnotations;
import com.mcpscanner.scan.McpScanLauncher;
import com.mcpscanner.scan.RunningScan;
import com.mcpscanner.scan.ScanActivity;
import com.mcpscanner.scan.ScanConnection;
import com.mcpscanner.scan.ScanGenerationSettings;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.scan.ScanModeSetting;
import com.mcpscanner.scan.request.ClientRegistrationRequestFactory;
import com.mcpscanner.scan.request.GeneratedScan;
import com.mcpscanner.scan.request.McpHttpRequestFactory;
import com.mcpscanner.scan.request.RequestFamily;
import com.mcpscanner.scan.request.ScanRequestRenderer;
import com.mcpscanner.testutil.InMemoryPersistedObject;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.SwingTree;
import com.mcpscanner.ui.connect.ConnectCoordinator;
import com.mcpscanner.ui.widgets.PrimaryActionButton;
import com.mcpscanner.ui.widgets.SideDrawer;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import java.awt.Container;
import java.awt.event.ActionEvent;
import java.net.URI;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.Optional;
import java.util.function.Supplier;

import static java.time.Duration.ofSeconds;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

final class McpScannerTabFixture {

    static final String ENDPOINT = "https://mcp.example.com/mcp";

    final PersistedObject store = mock(PersistedObject.class);
    final Logging logging = mock(Logging.class);
    final McpClientManager clientManager = mock(McpClientManager.class);
    final McpScannerSession session = mock(McpScannerSession.class);
    final McpScanLauncher scanLauncher = mock(McpScanLauncher.class);
    final ScanCheckRegistry checkRegistry = mock(ScanCheckRegistry.class);
    final ScanCheckSettings checkSettings = mock(ScanCheckSettings.class);
    final CurrentAuthHolder authHolder = new CurrentAuthHolder();
    final ScanGenerationSettings generationSettings;
    final ScanModeSetting scanModeSetting = spy(new ScanModeSetting(InMemoryPersistedObject.configStore()));
    final ExtensionConfigStore configStore;
    McpEventLog eventLog = new McpEventLog(null);
    final IdentityRegistry identities = new IdentityRegistry(
            new IdentityStore(InMemoryPersistedObject.configStore(), McpEventLog.noop()));
    final IdentityListings identityListings = new IdentityListings();
    final ComparedDiscovery comparedDiscovery =
            new ComparedDiscovery() {
                @Override
                public void discover(String identityId) {
                }

                @Override
                public boolean credentialChangedSinceDiscovery(String identityId) {
                    return false;
                }
            };
    final ToolCallRefusals toolCallRefusals = new ToolCallRefusals(identities);
    BiFunction<URI, OptionalGrantSettings, AuthStrategy> optionalGrants = ConnectCoordinator.NO_OPTIONAL_GRANTS;
    Map<String, String> scanOwnerArguments = Map.of();
    java.util.Set<String> scanMinedArguments = java.util.Set.of();
    WriteCallPrompt minedWritePrompt = (parent, lines) -> {
        throw new AssertionError("Unexpected mined write-tool confirmation: " + lines.items());
    };
    ToolsPrompt scanPrompt = (parent, tools, count, invoker) -> {
        throw new AssertionError("Unexpected destructive-scan confirmation for " + tools);
    };

    BurpNetworkingPrompt burpNetworkingPrompt = parent -> {
        throw new AssertionError("Unexpected Burp networking prompt");
    };

    ReconnectPrompt reconnectPrompt = (parent, user, previous) -> {
        throw new AssertionError("Unexpected reconnect prompt for " + user);
    };

    @FunctionalInterface
    interface ToolsPrompt {
        DestructiveScanConfirmation.Result ask(java.awt.Component parent,
                List<com.mcpscanner.mcp.McpToolDefinition> tools, int count, String invoker);
    }

    McpScannerTabFixture() {
        MontoyaTestFactory.install();
        when(store.getBoolean(anyString())).thenReturn(null);
        configStore = new ExtensionConfigStore(store, logging);
        generationSettings = new ScanGenerationSettings(InMemoryPersistedObject.configStore());
        when(session.scannerHeaders()).thenReturn(Map.of());
        when(session.resolvedEndpoint()).thenReturn(ENDPOINT);
        when(clientManager.scannerSession()).thenReturn(session);
        when(clientManager.isConnected()).thenReturn(true);
        when(checkRegistry.all()).thenReturn(List.of());
        stubScanLauncher();
    }

    private void stubScanLauncher() {
        when(scanLauncher.activity()).thenReturn(ScanActivity.idle());
        when(scanLauncher.launchScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), anyMap()))
                .thenReturn(mock(RunningScan.class));
        when(scanLauncher.captureConnection()).thenReturn(ScanConnection.unbound(ignored -> Map.of()));
        when(scanLauncher.captureScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), any(), any()))
                .thenAnswer(call -> launchingWith(call.getArgument(0), call.getArgument(1), call.getArgument(2),
                        call.getArgument(3)));
    }

    private Supplier<RunningScan> launchingWith(ScanMode mode, String endpoint, GeneratedScan scan,
                                               Supplier<Map<String, String>> headers) {
        return () -> scanLauncher.launchScan(mode, endpoint, scan, new HashMap<>(headers.get()));
    }

    McpScannerTab newTab() {
        return newTab(ServerConfigPanels.boundTo(configStore));
    }

    McpScannerTab newTab(ServerConfigPanel serverConfigPanel) {
        return new McpScannerTab(new McpScannerTabDependencies(clientManager, scanLauncher, logging, configStore,
                checkRegistry, checkSettings, eventLog, authHolder, generationSettings, scanModeSetting,
                new ScanRequestRenderer(new McpHttpRequestFactory(() -> 1L, PlainFraming.framer())::build,
                        new ClientRegistrationRequestFactory()), serverConfigPanel,
                () -> ScanConnection.unbound(ignored -> Map.of()), optionalGrants,
                new DestructiveScanPrompt() {
                    @Override
                    public DestructiveScanConfirmation.Result ask(java.awt.Component parent,
                            List<com.mcpscanner.mcp.McpToolDefinition> tools, int count, String invoker) {
                        return scanPrompt.ask(parent, tools, count, invoker);
                    }

                    @Override
                    public DestructiveScanConfirmation.Result askLines(java.awt.Component parent,
                            DestructiveScanConfirmation.Lines lines) {
                        return minedWritePrompt.ask(parent, lines);
                    }
                },
                parent -> burpNetworkingPrompt.offerToTurnOff(parent),
                new IdentityDependencies(identities, identityListings, comparedDiscovery, toolCallRefusals, this::identityCredentials,
                        (parent, user, previous) -> reconnectPrompt.confirm(parent, user, previous)),
                new com.mcpscanner.scan.OwnerArgumentSource() {
                    @Override
                    public Map<String, String> forTool(com.mcpscanner.mcp.McpToolDefinition tool) {
                        return scanOwnerArguments;
                    }

                    @Override
                    public java.util.Set<String> minedArgumentsFor(com.mcpscanner.mcp.McpToolDefinition tool) {
                        return scanMinedArguments;
                    }
                }, ManualReadScheduler.immediateReads(), TestDialogOwners.withoutSuiteFrame()));
    }

    private IdentityCredentialServices identityCredentials(SharedAuthSettings sharedClient,
                                                           ScopeApprovals approvals) {
        return IdentityCredentialServices.create(identities, sharedClient,
                (identity, hints) -> new BearerTokenAuthStrategy("signed-in-" + identity.name()),
                Executors.newSingleThreadExecutor(), McpEventLog.noop());
    }

    void useAuth(String authType) {
        when(store.getBoolean("mcp.auth.auto_detect")).thenReturn(!AuthTypeNames.NONE.equals(authType));
        Identity user = identities.primaryUser();
        IdentityAuthKind kind = kindOf(authType);
        if (user.authKind() != kind) {
            identities.update(user.withAuthKind(kind));
        }
    }

    private static IdentityAuthKind kindOf(String authType) {
        return switch (authType) {
            case AuthTypeNames.BEARER -> IdentityAuthKind.BEARER;
            case AuthTypeNames.CUSTOM_HEADERS -> IdentityAuthKind.CUSTOM_HEADERS;
            case AuthTypeNames.OAUTH -> IdentityAuthKind.OAUTH;
            default -> IdentityAuthKind.NONE;
        };
    }

    void sendOnlyItemInvocations() {
        Arrays.stream(RequestFamily.values())
                .forEach(family -> generationSettings.setEnabled(family, family.group().invokesInventoryItems()));
    }

    McpScannerTab connected(ConnectResult result) throws Exception {
        return connected(result, tab -> { });
    }

    McpScannerTab connected(ConnectResult result, Consumer<McpScannerTab> beforeConnect) throws Exception {
        McpScannerTab tab = fromEdt(this::newTab);
        onEdt(() -> beforeConnect.accept(tab));
        connect(tab, result);
        return tab;
    }

    McpScannerTab connectedWithAuth(AuthStrategy auth, ConnectResult result) throws Exception {
        optionalGrants = (endpoint, settings) -> auth;
        McpScannerTab tab = fromEdt(this::newTab);
        when(clientManager.connect(any())).thenReturn(result);
        onEdt(() -> {
            endpointField(tab).setText(ENDPOINT);
            identities.update(identities.primaryUser().withAuthKind(IdentityAuthKind.OAUTH_CLIENT_CREDENTIALS));
            fillGrant(serverConfig(tab), OptionalGrantSettings.Profile.CLIENT_CREDENTIALS, "client", "secret");
            click(connectButton(tab));
        });
        awaitConnectLabel(tab, "Disconnect");
        return tab;
    }

    McpScannerTab connecting(java.util.concurrent.CompletableFuture<Void> gate) throws Exception {
        when(clientManager.connect(any())).thenAnswer(call -> {
            gate.get();
            return emptyInventory();
        });
        McpScannerTab tab = fromEdt(this::newTab);
        onEdt(() -> {
            endpointField(tab).setText(ENDPOINT);
            useAuth(AuthTypeNames.NONE);
            click(connectButton(tab));
        });
        awaitConnectLabel(tab, "Cancel");
        return tab;
    }

    void connect(McpScannerTab tab, ConnectResult result) throws Exception {
        when(clientManager.connect(any())).thenReturn(result);
        onEdt(() -> {
            endpointField(tab).setText(ENDPOINT);
            useAuth(AuthTypeNames.NONE);
            click(connectButton(tab));
        });
        awaitConnectLabel(tab, "Disconnect");
    }

    static void awaitConnectLabel(McpScannerTab tab, String label) {
        await().atMost(ofSeconds(5)).until(() -> fromEdt(() -> connectButton(tab).getText()).equals(label));
    }

    static void awaitDisconnected(McpScannerTab tab) {
        awaitConnectLabel(tab, "Connect");
        await().atMost(ofSeconds(5)).until(() -> !String.valueOf(fromEdt(() -> connectButton(tab).getToolTipText()))
                .contains(McpScannerTab.DISCONNECTING));
    }

    static void awaitStatus(McpScannerTab tab, String prefix) {
        await().atMost(ofSeconds(5)).until(() -> fromEdt(() -> statusText(tab)).startsWith(prefix));
    }

    static ConnectResult inventory(List<McpToolDefinition> tools) {
        return new ConnectResult(tools, List.of(), List.of(), List.of(), ServerMetadata.empty());
    }

    static ConnectResult emptyInventory() {
        return inventory(List.of());
    }

    static McpToolDefinition readOnlyTool(String name) {
        return new McpToolDefinition(name, "", "{}", List.of(), new ToolAnnotations(null, true, null, null, null));
    }

    static McpToolDefinition destructiveTool(String name) {
        return new McpToolDefinition(name, "", "{}", List.of(), new ToolAnnotations(null, false, true, null, null));
    }

    static <T> T find(Container root, Class<T> type) {
        return SwingTree.descendants(root).stream().filter(type::isInstance).map(type::cast)
                .findFirst().orElseThrow(() -> new AssertionError("No " + type.getSimpleName() + " in the tab"));
    }

    static ConnectionHeader header(McpScannerTab tab) {
        return find(tab, ConnectionHeader.class);
    }

    static JTextField endpointField(McpScannerTab tab) {
        return header(tab).endpointField();
    }

    static JComboBox<com.mcpscanner.client.TransportType> transportCombo(McpScannerTab tab) {
        return header(tab).transportCombo();
    }

    static PrimaryActionButton connectButton(McpScannerTab tab) {
        return header(tab).connectButton();
    }

    static String statusText(McpScannerTab tab) {
        return header(tab).statusCluster().statusText();
    }

    static ScanBar scanBar(McpScannerTab tab) {
        return find(tab, ScanBar.class);
    }

    static PrimaryActionButton scanButton(McpScannerTab tab) {
        return scanBar(tab).scanButton();
    }

    static SideDrawer drawer(McpScannerTab tab) {
        return find(tab, SideDrawer.class);
    }

    static ToolTablePanel tools(McpScannerTab tab) {
        return find(tab, ToolTablePanel.class);
    }

    static ResourceTablePanel resources(McpScannerTab tab) {
        return find(tab, ResourceTablePanel.class);
    }

    static ResourceTemplateTablePanel templates(McpScannerTab tab) {
        return find(tab, ResourceTemplateTablePanel.class);
    }

    static PromptTablePanel prompts(McpScannerTab tab) {
        return find(tab, PromptTablePanel.class);
    }

    static ServerConfigPanel serverConfig(McpScannerTab tab) {
        return find(tab, ServerConfigPanel.class);
    }

    static OAuthClientSection oauthClient(McpScannerTab tab) {
        return find(tab, OAuthClientSection.class);
    }

    static void fillGrant(ServerConfigPanel panel, OptionalGrantSettings.Profile profile, String clientId,
                          String secret) {
        OptionalGrantFields fields = panel.grantForms().fieldsFor(profile);
        fields.issuerField().setText("https://issuer.example");
        fields.clientIdField().setText(clientId);
        fields.secretField().setText(secret);
    }

    static void click(JButton button) {
        for (var listener : button.getActionListeners()) {
            listener.actionPerformed(new ActionEvent(button, ActionEvent.ACTION_PERFORMED, button.getActionCommand()));
        }
    }

    static void flushEdt() throws Exception {
        onEdt(() -> { });
    }

    static void onEdt(ThrowingRunnable runnable) throws Exception {
        fromEdt(() -> {
            runnable.run();
            return null;
        });
    }

    static <T> T fromEdt(Callable<T> callable) throws Exception {
        if (SwingUtilities.isEventDispatchThread()) {
            return callable.call();
        }
        AtomicReference<T> result = new AtomicReference<>();
        AtomicReference<Exception> failure = new AtomicReference<>();
        AtomicReference<Error> error = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                result.set(callable.call());
            } catch (Exception e) {
                failure.set(e);
            } catch (Error e) {
                error.set(e);
            }
        });
        if (error.get() != null) {
            throw error.get();
        }
        if (failure.get() != null) {
            throw failure.get();
        }
        return result.get();
    }

    @FunctionalInterface
    interface ThrowingRunnable {
        void run() throws Exception;
    }
}
