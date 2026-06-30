package com.mcpscanner.ui;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.CurrentAuthHolder;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.auth.oauth.discovery.DiscoveryFailedException;
import com.mcpscanner.auth.oauth.discovery.DiscoverySource;
import com.mcpscanner.checks.registry.ScanCheckRegistry;
import com.mcpscanner.checks.registry.ScanCheckSettings;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.McpScannerSession;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ToolAnnotations;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.scan.CurrentSelectionHolder;
import com.mcpscanner.scan.McpScanLauncher;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.mcpscanner.testutil.TestOAuthFlows;
import com.mcpscanner.ui.state.Cancellable;
import com.mcpscanner.ui.state.ConnectAttempt;
import com.mcpscanner.ui.state.ConnectPhase;
import com.mcpscanner.ui.state.ConnectionStatus;
import com.mcpscanner.ui.state.UiConnectionState;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.client.TransportType;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.swing.JButton;
import javax.swing.SwingUtilities;
import java.awt.event.ActionEvent;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class McpScannerTabTest {

    @BeforeAll
    static void installMontoyaFactory() {
        MontoyaTestFactory.install();
    }

    private McpClientManager clientManager;
    private McpScanLauncher scanLauncher;
    private Logging logging;
    private ExtensionConfigStore configStore;
    private ScanCheckRegistry checkRegistry;
    private ScanCheckSettings checkSettings;
    private PersistedObject store;
    private CurrentAuthHolder authHolder;
    private CurrentSelectionHolder selectionHolder;

    @BeforeEach
    void setUp() {
        store = mock(PersistedObject.class);
        when(store.getBoolean(anyString())).thenReturn(null);
        logging = mock(Logging.class);
        clientManager = mock(McpClientManager.class);
        scanLauncher = mock(McpScanLauncher.class);
        configStore = new ExtensionConfigStore(store, logging);
        checkRegistry = mock(ScanCheckRegistry.class);
        checkSettings = mock(ScanCheckSettings.class);
        when(checkRegistry.all()).thenReturn(List.of());
        McpScannerSession scannerSession = mock(McpScannerSession.class);
        when(scannerSession.scannerHeaders()).thenReturn(Map.of());
        when(scannerSession.resolvedEndpoint()).thenReturn("https://mcp.example.com/mcp");
        when(clientManager.scannerSession()).thenReturn(scannerSession);
        when(clientManager.isConnected()).thenReturn(true);
        authHolder = new CurrentAuthHolder();
        selectionHolder = new CurrentSelectionHolder();
    }

    private McpScannerTab newTab() {
        return new McpScannerTab(clientManager, scanLauncher, logging, configStore,
                checkRegistry, checkSettings, new McpEventLog(null), authHolder, selectionHolder,
                TestOAuthFlows.recording());
    }

    private McpScannerTab newTabWith(ServerConfigPanel serverConfigPanel) {
        return new McpScannerTab(clientManager, scanLauncher, logging, configStore,
                checkRegistry, checkSettings, new McpEventLog(null), authHolder, selectionHolder,
                serverConfigPanel);
    }

    @Test
    void scanPublishesCurrentAuthStrategyBeforeLaunch() throws Exception {
        CountDownLatch launched = new CountDownLatch(1);
        AtomicReference<AuthStrategy> publishedAtLaunch = new AtomicReference<>();
        doAnswer(inv -> {
            publishedAtLaunch.set(authHolder.get());
            launched.countDown();
            return null;
        }).when(scanLauncher).launchScan(anyString(), any(ScanInventory.class), anyMap());

        AuthStrategy customStrategy = Map::of;

        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setAuthStrategyOverrideForTest(customStrategy);
            tab.populateToolsForTest(List.of(readOnlyTool("echo", "")));
            clickButton(tab.scanButtonForTest());
        });

        assertThat(launched.await(5, TimeUnit.SECONDS)).isTrue();
        drainSwingEvents();

        assertThat(publishedAtLaunch.get()).isSameAs(customStrategy);
        assertThat(authHolder.get()).isSameAs(customStrategy);
    }

    @Test
    void publishesSelectedInventoryToHolderOnScanLaunch() throws Exception {
        CountDownLatch launched = new CountDownLatch(1);
        AtomicReference<ScanInventory> publishedAtLaunch = new AtomicReference<>();
        doAnswer(inv -> {
            publishedAtLaunch.set(selectionHolder.get());
            launched.countDown();
            return null;
        }).when(scanLauncher).launchScan(anyString(), any(ScanInventory.class), anyMap());

        McpToolDefinition selectedTool = readOnlyTool("echo", "");

        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setAuthStrategyOverrideForTest(Map::of);
            tab.populateToolsForTest(List.of(selectedTool));
            clickButton(tab.scanButtonForTest());
        });

        assertThat(launched.await(5, TimeUnit.SECONDS)).isTrue();
        drainSwingEvents();

        assertThat(publishedAtLaunch.get()).isNotNull();
        assertThat(publishedAtLaunch.get().tools()).containsExactly(selectedTool);
        assertThat(selectionHolder.get().tools()).containsExactly(selectedTool);
    }

    @Test
    void onScanInvokesAuthStrategyHeadersOffEdt() throws Exception {
        AtomicReference<Boolean> capturedEdtFlag = new AtomicReference<>();
        CountDownLatch headersInvoked = new CountDownLatch(1);
        AuthStrategy edtRecordingStrategy = () -> {
            capturedEdtFlag.set(SwingUtilities.isEventDispatchThread());
            headersInvoked.countDown();
            return Map.of();
        };

        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setAuthStrategyOverrideForTest(edtRecordingStrategy);
            tab.populateToolsForTest(List.of(readOnlyTool("echo", "desc")));
            clickButton(tab.scanButtonForTest());
        });

        assertThat(headersInvoked.await(5, TimeUnit.SECONDS)).isTrue();
        drainSwingEvents();

        assertThat(capturedEdtFlag.get()).isFalse();
    }

    @Test
    void onScanPassesOnlySelectedItemsToLauncher() throws Exception {
        CountDownLatch launched = new CountDownLatch(1);
        AtomicReference<ScanInventory> captured = new AtomicReference<>();
        doAnswer(inv -> {
            captured.set(inv.getArgument(1));
            launched.countDown();
            return null;
        }).when(scanLauncher).launchScan(anyString(), any(ScanInventory.class), anyMap());

        McpToolDefinition toolKept = readOnlyTool("kept-tool", "");
        McpToolDefinition toolSkipped = readOnlyTool("skipped-tool", "");
        McpResourceDefinition resKept = new McpResourceDefinition("docs://keep", "k", "", "text/plain");
        McpResourceDefinition resSkipped = new McpResourceDefinition("docs://drop", "d", "", "text/plain");
        McpResourceTemplateDefinition tplKept = new McpResourceTemplateDefinition(
                "tmpl://keep/{x}", "tk", "", "text/plain");
        McpResourceTemplateDefinition tplSkipped = new McpResourceTemplateDefinition(
                "tmpl://drop/{x}", "td", "", "text/plain");
        McpPromptDefinition promptKept = new McpPromptDefinition("pkeep", "", List.of());
        McpPromptDefinition promptSkipped = new McpPromptDefinition("pdrop", "", List.of());

        ConnectResult result = new ConnectResult(
                List.of(toolKept, toolSkipped),
                List.of(resKept, resSkipped),
                List.of(tplKept, tplSkipped),
                List.of(promptKept, promptSkipped),
                ServerMetadata.empty());

        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setAuthStrategyOverrideForTest(Map::of);
            tab.setStateForTest(UiConnectionState.connected(result, "mcp.example.com",
                    ConnectionStatus.connected("user", "mcp.example.com", null, 0)));
            tab.populateAllInventoriesForTest(result);
            tab.resourceTablePanelForTest().getTableModel().setValueAt(false, 1, 0);
            tab.resourceTemplateTablePanelForTest().getTableModel().setValueAt(false, 1, 0);
            tab.promptTablePanelForTest().getTableModel().setValueAt(false, 1, 0);
            tab.toolTablePanelForTest().getTableModel().setValueAt(false, 1, 0);
            clickButton(tab.scanButtonForTest());
        });

        assertThat(launched.await(5, TimeUnit.SECONDS)).isTrue();
        drainSwingEvents();

        ScanInventory inventory = captured.get();
        assertThat(inventory.tools()).containsExactly(toolKept);
        assertThat(inventory.resources()).containsExactly(resKept);
        assertThat(inventory.resourceTemplates()).containsExactly(tplKept);
        assertThat(inventory.prompts()).containsExactly(promptKept);
    }

    @Test
    void scanButtonEnabledWhenOnlyResourcesSelected() throws Exception {
        ConnectResult result = new ConnectResult(
                List.<McpToolDefinition>of(),
                List.of(new McpResourceDefinition("docs://keep", "k", "", "text/plain")),
                List.<McpResourceTemplateDefinition>of(),
                List.<McpPromptDefinition>of(),
                ServerMetadata.empty());

        AtomicReference<JButton> scanButton = new AtomicReference<>();
        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.populateAllInventoriesForTest(result);
            tab.setStateForTest(UiConnectionState.connected(result, "mcp.example.com",
                    ConnectionStatus.connected("user", "mcp.example.com", null, 0)));
            scanButton.set(tab.scanButtonForTest());
        });

        assertThat(scanButton.get().isEnabled()).isTrue();
    }

    @Test
    void scanButtonEnabledWhenOnlyResourceTemplatesSelected() throws Exception {
        ConnectResult result = new ConnectResult(
                List.<McpToolDefinition>of(),
                List.<McpResourceDefinition>of(),
                List.of(new McpResourceTemplateDefinition("tmpl://keep/{x}", "tk", "", "text/plain")),
                List.<McpPromptDefinition>of(),
                ServerMetadata.empty());

        AtomicReference<JButton> scanButton = new AtomicReference<>();
        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.populateAllInventoriesForTest(result);
            tab.setStateForTest(UiConnectionState.connected(result, "mcp.example.com",
                    ConnectionStatus.connected("user", "mcp.example.com", null, 0)));
            scanButton.set(tab.scanButtonForTest());
        });

        assertThat(scanButton.get().isEnabled()).isTrue();
    }

    @Test
    void scanButtonEnabledWhenOnlyPromptsSelected() throws Exception {
        ConnectResult result = new ConnectResult(
                List.<McpToolDefinition>of(),
                List.<McpResourceDefinition>of(),
                List.<McpResourceTemplateDefinition>of(),
                List.of(new McpPromptDefinition("pkeep", "", List.of())),
                ServerMetadata.empty());

        AtomicReference<JButton> scanButton = new AtomicReference<>();
        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.populateAllInventoriesForTest(result);
            tab.setStateForTest(UiConnectionState.connected(result, "mcp.example.com",
                    ConnectionStatus.connected("user", "mcp.example.com", null, 0)));
            scanButton.set(tab.scanButtonForTest());
        });

        assertThat(scanButton.get().isEnabled()).isTrue();
    }

    @Test
    void scanButtonDisabledWhenAllPanelsHaveNoSelections() throws Exception {
        McpToolDefinition tool = new McpToolDefinition("echo", "", "{}");
        McpResourceDefinition resource = new McpResourceDefinition("docs://drop", "d", "", "text/plain");
        McpResourceTemplateDefinition template = new McpResourceTemplateDefinition(
                "tmpl://drop/{x}", "td", "", "text/plain");
        McpPromptDefinition prompt = new McpPromptDefinition("pdrop", "", List.of());
        ConnectResult result = new ConnectResult(
                List.of(tool), List.of(resource), List.of(template), List.of(prompt),
                ServerMetadata.empty());

        AtomicReference<JButton> scanButton = new AtomicReference<>();
        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setStateForTest(UiConnectionState.connected(result, "mcp.example.com",
                    ConnectionStatus.connected("user", "mcp.example.com", null, 0)));
            tab.populateAllInventoriesForTest(result);
            tab.toolTablePanelForTest().getTableModel().setValueAt(false, 0, 0);
            tab.resourceTablePanelForTest().getTableModel().setValueAt(false, 0, 0);
            tab.resourceTemplateTablePanelForTest().getTableModel().setValueAt(false, 0, 0);
            tab.promptTablePanelForTest().getTableModel().setValueAt(false, 0, 0);
            scanButton.set(tab.scanButtonForTest());
        });

        assertThat(scanButton.get().isEnabled()).isFalse();
    }

    @Test
    void scanButtonTogglesAsResourceSelectionsChange() throws Exception {
        ConnectResult result = new ConnectResult(
                List.<McpToolDefinition>of(),
                List.of(new McpResourceDefinition("docs://keep", "k", "", "text/plain")),
                List.<McpResourceTemplateDefinition>of(),
                List.<McpPromptDefinition>of(),
                ServerMetadata.empty());

        AtomicReference<McpScannerTab> tabRef = new AtomicReference<>();
        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.populateAllInventoriesForTest(result);
            tab.setStateForTest(UiConnectionState.connected(result, "mcp.example.com",
                    ConnectionStatus.connected("user", "mcp.example.com", null, 0)));
            tabRef.set(tab);
        });

        assertThat(tabRef.get().scanButtonForTest().isEnabled()).isTrue();

        invokeAndWait(() ->
                tabRef.get().resourceTablePanelForTest().getTableModel().setValueAt(false, 0, 0));
        assertThat(tabRef.get().scanButtonForTest().isEnabled()).isFalse();

        invokeAndWait(() ->
                tabRef.get().resourceTablePanelForTest().getTableModel().setValueAt(true, 0, 0));
        assertThat(tabRef.get().scanButtonForTest().isEnabled()).isTrue();
    }

    @Test
    void onDisconnectInvokesClientManagerDisconnectOffEdt() throws Exception {
        AtomicReference<Boolean> capturedEdtFlag = new AtomicReference<>();
        CountDownLatch disconnectInvoked = new CountDownLatch(1);
        doAnswer(inv -> {
            capturedEdtFlag.set(SwingUtilities.isEventDispatchThread());
            disconnectInvoked.countDown();
            return null;
        }).when(clientManager).disconnect();

        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setStateForTest(UiConnectionState.connected(
                    emptyConnectResult(), "mcp.example.com",
                    ConnectionStatus.connected("user", "mcp.example.com", null, 0)));
            clickButton(tab.primaryButtonForTest());
        });

        assertThat(disconnectInvoked.await(5, TimeUnit.SECONDS)).isTrue();
        drainSwingEvents();

        assertThat(capturedEdtFlag.get()).isFalse();
    }

    @Test
    void disconnectFailureIsLoggedToErrorStream() throws Exception {
        doThrow(new RuntimeException("disconnect boom")).when(clientManager).disconnect();

        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setStateForTest(UiConnectionState.connected(
                    emptyConnectResult(), "mcp.example.com",
                    ConnectionStatus.connected("user", "mcp.example.com", null, 0)));
            clickButton(tab.primaryButtonForTest());
        });

        await().atMost(ofSeconds(5)).untilAsserted(() -> {
            drainSwingEvents();
            verify(logging).logToError(org.mockito.ArgumentMatchers.contains("disconnect boom"));
        });
    }

    @Test
    void shutdownCancelsActiveScans() throws Exception {
        AtomicReference<McpScannerTab> tabRef = new AtomicReference<>();
        invokeAndWait(() -> tabRef.set(newTab()));

        tabRef.get().shutdown();

        verify(scanLauncher).cancelActiveScans();
    }

    @Test
    void onCancelDispatchesDisconnectOffEdt() throws Exception {
        AtomicReference<Boolean> capturedEdtFlag = new AtomicReference<>();
        CountDownLatch disconnectStarted = new CountDownLatch(1);
        CountDownLatch disconnectMayProceed = new CountDownLatch(1);
        doAnswer(inv -> {
            capturedEdtFlag.set(SwingUtilities.isEventDispatchThread());
            disconnectStarted.countDown();
            disconnectMayProceed.await(5, TimeUnit.SECONDS);
            return null;
        }).when(clientManager).disconnect();

        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setStateForTest(UiConnectionState.connecting(
                    ConnectAttempt.withSnapshot("https://mcp.example.com/mcp",
                            TransportType.STREAMABLE_HTTP, "mcp.example.com",
                            "None", null),
                    Cancellable.NOOP, ConnectPhase.CONNECT, "Connecting…"));
            clickButton(tab.primaryButtonForTest());
        });

        assertThat(disconnectStarted.await(5, TimeUnit.SECONDS)).isTrue();

        AtomicBoolean edtRanWhileDisconnecting = new AtomicBoolean(false);
        CountDownLatch edtPing = new CountDownLatch(1);
        SwingUtilities.invokeLater(() -> {
            edtRanWhileDisconnecting.set(true);
            edtPing.countDown();
        });
        assertThat(edtPing.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(edtRanWhileDisconnecting).isTrue();

        disconnectMayProceed.countDown();
        drainSwingEvents();

        assertThat(capturedEdtFlag.get()).isFalse();
    }

    @Test
    void onScanSkipsModalWhenAllSelectedToolsAreReadOnly() throws Exception {
        CountDownLatch launched = new CountDownLatch(1);
        AtomicBoolean promptInvoked = new AtomicBoolean(false);
        doAnswer(inv -> {
            launched.countDown();
            return null;
        }).when(scanLauncher).launchScan(anyString(), any(ScanInventory.class), anyMap());

        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setAuthStrategyOverrideForTest(Map::of);
            tab.setConfirmationPromptForTest(tools -> {
                promptInvoked.set(true);
                return new DestructiveScanConfirmation.Result(false, false);
            });
            tab.populateToolsForTest(List.of(readOnlyTool("safe", "")));
            clickButton(tab.scanButtonForTest());
        });

        assertThat(launched.await(5, TimeUnit.SECONDS)).isTrue();
        drainSwingEvents();
        assertThat(promptInvoked).isFalse();
    }

    @Test
    void onScanSkipsModalWhenDontAskAgainIsSet() throws Exception {
        when(store.getBoolean(anyString())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            return key.endsWith(".dontAskAgain") ? Boolean.TRUE : null;
        });
        CountDownLatch launched = new CountDownLatch(1);
        AtomicBoolean promptInvoked = new AtomicBoolean(false);
        doAnswer(inv -> {
            launched.countDown();
            return null;
        }).when(scanLauncher).launchScan(anyString(), any(ScanInventory.class), anyMap());

        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setAuthStrategyOverrideForTest(Map::of);
            tab.setConfirmationPromptForTest(tools -> {
                promptInvoked.set(true);
                return new DestructiveScanConfirmation.Result(false, false);
            });
            tab.populateToolsForTest(List.of(destructiveTool("destroy")));
            tab.toolTablePanelForTest().getTableModel().setValueAt(true, 0, 0);
            clickButton(tab.scanButtonForTest());
        });

        assertThat(launched.await(5, TimeUnit.SECONDS)).isTrue();
        drainSwingEvents();
        assertThat(promptInvoked).isFalse();
    }

    @Test
    void onScanShowsModalAndProceedsWhenUserConfirms() throws Exception {
        CountDownLatch launched = new CountDownLatch(1);
        AtomicBoolean promptInvoked = new AtomicBoolean(false);
        doAnswer(inv -> {
            launched.countDown();
            return null;
        }).when(scanLauncher).launchScan(anyString(), any(ScanInventory.class), anyMap());

        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setAuthStrategyOverrideForTest(Map::of);
            tab.setConfirmationPromptForTest(tools -> {
                promptInvoked.set(true);
                return new DestructiveScanConfirmation.Result(true, false);
            });
            tab.populateToolsForTest(List.of(destructiveTool("destroy")));
            tab.toolTablePanelForTest().getTableModel().setValueAt(true, 0, 0);
            clickButton(tab.scanButtonForTest());
        });

        assertThat(launched.await(5, TimeUnit.SECONDS)).isTrue();
        drainSwingEvents();
        assertThat(promptInvoked).isTrue();
    }

    @Test
    void onScanPersistsDontAskAgainWhenCheckboxTicked() throws Exception {
        CountDownLatch launched = new CountDownLatch(1);
        doAnswer(inv -> {
            launched.countDown();
            return null;
        }).when(scanLauncher).launchScan(anyString(), any(ScanInventory.class), anyMap());

        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setAuthStrategyOverrideForTest(Map::of);
            tab.setConfirmationPromptForTest(tools ->
                    new DestructiveScanConfirmation.Result(true, true));
            tab.populateToolsForTest(List.of(destructiveTool("destroy")));
            tab.toolTablePanelForTest().getTableModel().setValueAt(true, 0, 0);
            clickButton(tab.scanButtonForTest());
        });

        assertThat(launched.await(5, TimeUnit.SECONDS)).isTrue();
        drainSwingEvents();
        org.mockito.Mockito.verify(store).setBoolean(
                org.mockito.ArgumentMatchers.endsWith(".dontAskAgain"),
                org.mockito.ArgumentMatchers.eq(true));
    }

    @Test
    void onScanCancelsWhenUserDismissesModal() throws Exception {
        AtomicBoolean promptInvoked = new AtomicBoolean(false);

        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setAuthStrategyOverrideForTest(Map::of);
            tab.setConfirmationPromptForTest(tools -> {
                promptInvoked.set(true);
                return new DestructiveScanConfirmation.Result(false, false);
            });
            tab.populateToolsForTest(List.of(destructiveTool("destroy")));
            tab.toolTablePanelForTest().getTableModel().setValueAt(true, 0, 0);
            clickButton(tab.scanButtonForTest());
        });

        drainSwingEvents();
        assertThat(promptInvoked).isTrue();
        org.mockito.Mockito.verify(scanLauncher, org.mockito.Mockito.never())
                .launchScan(anyString(), any(ScanInventory.class), anyMap());
    }

    @Test
    void rapidScanClicksStillLaunchAllScans() throws Exception {
        CountDownLatch firstLaunched = new CountDownLatch(1);
        CountDownLatch secondLaunched = new CountDownLatch(2);
        doAnswer(inv -> {
            firstLaunched.countDown();
            secondLaunched.countDown();
            return null;
        }).when(scanLauncher).launchScan(anyString(), any(ScanInventory.class), anyMap());

        McpToolDefinition tool = readOnlyTool("echo", "");
        ConnectResult result = new ConnectResult(
                List.of(tool),
                List.<McpResourceDefinition>of(),
                List.<McpResourceTemplateDefinition>of(),
                List.<McpPromptDefinition>of(),
                ServerMetadata.empty());

        AtomicReference<JButton> scanButton = new AtomicReference<>();
        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setAuthStrategyOverrideForTest(Map::of);
            tab.populateAllInventoriesForTest(result);
            tab.setStateForTest(UiConnectionState.connected(result, "mcp.example.com",
                    ConnectionStatus.connected("user", "mcp.example.com", null, 1)));
            scanButton.set(tab.scanButtonForTest());
            clickButton(tab.scanButtonForTest());
        });

        assertThat(firstLaunched.await(5, TimeUnit.SECONDS)).isTrue();
        drainSwingEvents();

        invokeAndWait(() -> clickButton(scanButton.get()));
        assertThat(secondLaunched.await(5, TimeUnit.SECONDS)).isTrue();
        drainSwingEvents();

        org.mockito.Mockito.verify(scanLauncher, org.mockito.Mockito.times(2))
                .launchScan(anyString(), any(ScanInventory.class), anyMap());
    }

    @Test
    void scanButtonShowsLaunchedFeedbackForBriefPeriod() throws Exception {
        AtomicReference<JButton> scanButton = new AtomicReference<>();
        AtomicReference<String> labelAfterClick = new AtomicReference<>();
        AtomicBoolean enabledAfterClick = new AtomicBoolean();
        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setAuthStrategyOverrideForTest(Map::of);
            tab.populateToolsForTest(List.of(readOnlyTool("echo", "")));
            scanButton.set(tab.scanButtonForTest());
            clickButton(tab.scanButtonForTest());
            labelAfterClick.set(scanButton.get().getText());
            enabledAfterClick.set(scanButton.get().isEnabled());
        });

        assertThat(labelAfterClick.get()).isEqualTo("Scan launched ✓");
        assertThat(enabledAfterClick.get()).isFalse();
    }

    @Test
    void eventLogReceivesScanStartedMessageOnClick() throws Exception {
        CountDownLatch launched = new CountDownLatch(1);
        doAnswer(inv -> {
            launched.countDown();
            return null;
        }).when(scanLauncher).launchScan(anyString(), any(ScanInventory.class), anyMap());

        McpEventLog spyLog = org.mockito.Mockito.spy(new McpEventLog(null));

        invokeAndWait(() -> {
            McpScannerTab tab = new McpScannerTab(clientManager, scanLauncher, logging, configStore,
                    checkRegistry, checkSettings, spyLog, authHolder, selectionHolder,
                    TestOAuthFlows.recording());
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.setAuthStrategyOverrideForTest(Map::of);
            tab.populateToolsForTest(List.of(readOnlyTool("echo", "")));
            clickButton(tab.scanButtonForTest());
        });

        assertThat(launched.await(5, TimeUnit.SECONDS)).isTrue();
        drainSwingEvents();

        org.mockito.ArgumentCaptor<String> messageCaptor = org.mockito.ArgumentCaptor.forClass(String.class);
        org.mockito.Mockito.verify(spyLog, org.mockito.Mockito.atLeastOnce()).info(messageCaptor.capture());
        assertThat(messageCaptor.getAllValues())
                .anySatisfy(message -> assertThat(message).contains("Scan started"));
    }

    @Test
    void connectWithEmptyIssuerTriggersAutoDiscovery() throws Exception {
        DiscoveredMetadata metadata = new DiscoveredMetadata(
                URI.create("https://issuer.example"),
                DiscoverySource.AS_WELL_KNOWN,
                null);
        ConnectResult fakeResult = emptyConnectResult();
        when(clientManager.connect(any())).thenReturn(fakeResult);

        AtomicReference<OAuthClientHints> hintsPassedToDance = new AtomicReference<>();
        OAuthAuthCodeStrategy fakeStrategy = mock(OAuthAuthCodeStrategy.class);

        AtomicReference<ServerConfigPanel> spyRef = new AtomicReference<>();
        CountDownLatch danceDone = new CountDownLatch(1);

        invokeAndWait(() -> {
            ServerConfigPanel basePanel = new ServerConfigPanel(configStore, TestOAuthFlows.recording());
            ServerConfigPanel spyPanel = spy(basePanel);
            doReturn(metadata).when(spyPanel).discoverOauthMetadataSync(anyString());
            doAnswer(inv -> {
                hintsPassedToDance.set(inv.getArgument(0));
                danceDone.countDown();
                return fakeStrategy;
            }).when(spyPanel).completeOAuthDance(any(), any(), any(), any());

            spyPanel.getOauthIssuerField().setText("");
            McpScannerTab tab = newTabWith(spyPanel);
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.authTypeComboForTest().setSelectedItem(ServerConfigPanel.AUTH_OAUTH);
            spyRef.set(spyPanel);
            clickButton(tab.primaryButtonForTest());
        });

        assertThat(danceDone.await(5, TimeUnit.SECONDS)).isTrue();
        drainSwingEvents();

        verify(spyRef.get()).discoverOauthMetadataSync("https://mcp.example.com/mcp");
        verify(spyRef.get()).applyDiscoveredMetadata(metadata);
        assertThat(hintsPassedToDance.get()).isNotNull();
        assertThat(hintsPassedToDance.get().issuer()).isEqualTo(URI.create("https://issuer.example"));
        assertThat(spyRef.get().getOauthIssuerField().getText()).isEqualTo("https://issuer.example");
    }

    @Test
    void connectWithManualIssuerSkipsAutoDiscovery() throws Exception {
        ConnectResult fakeResult = emptyConnectResult();
        when(clientManager.connect(any())).thenReturn(fakeResult);

        OAuthAuthCodeStrategy fakeStrategy = mock(OAuthAuthCodeStrategy.class);
        AtomicReference<ServerConfigPanel> spyRef = new AtomicReference<>();
        CountDownLatch danceDone = new CountDownLatch(1);

        invokeAndWait(() -> {
            ServerConfigPanel basePanel = new ServerConfigPanel(configStore, TestOAuthFlows.recording());
            ServerConfigPanel spyPanel = spy(basePanel);
            doAnswer(inv -> {
                danceDone.countDown();
                return fakeStrategy;
            }).when(spyPanel).completeOAuthDance(any(), any(), any(), any());

            spyPanel.getOauthIssuerField().setText("https://manual.issuer.example");
            McpScannerTab tab = newTabWith(spyPanel);
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.authTypeComboForTest().setSelectedItem(ServerConfigPanel.AUTH_OAUTH);
            spyRef.set(spyPanel);
            clickButton(tab.primaryButtonForTest());
        });

        assertThat(danceDone.await(5, TimeUnit.SECONDS)).isTrue();
        drainSwingEvents();

        verify(spyRef.get(), never()).discoverOauthMetadataSync(anyString());
        verify(spyRef.get(), never()).applyDiscoveredMetadata(any());
    }

    @Test
    void autoDiscoveryFailureTransitionsToFailedState() throws Exception {
        AtomicReference<McpScannerTab> tabRef = new AtomicReference<>();

        invokeAndWait(() -> {
            ServerConfigPanel basePanel = new ServerConfigPanel(configStore, TestOAuthFlows.recording());
            ServerConfigPanel spyPanel = spy(basePanel);
            doThrow(new DiscoveryFailedException("no metadata at any standard path"))
                    .when(spyPanel).discoverOauthMetadataSync(anyString());

            spyPanel.getOauthIssuerField().setText("");
            McpScannerTab tab = newTabWith(spyPanel);
            tab.endpointFieldForTest().setText("https://mcp.example.com/mcp");
            tab.authTypeComboForTest().setSelectedItem(ServerConfigPanel.AUTH_OAUTH);
            tabRef.set(tab);
            clickButton(tab.primaryButtonForTest());
        });

        await().atMost(ofSeconds(5)).until(() -> {
            drainSwingEvents();
            return tabRef.get().stateForTest() instanceof UiConnectionState.Failed;
        });

        UiConnectionState finalState = tabRef.get().stateForTest();
        assertThat(finalState).isInstanceOf(UiConnectionState.Failed.class);
        UiConnectionState.Failed failed = (UiConnectionState.Failed) finalState;
        assertThat(failed.phase()).isEqualTo(ConnectPhase.DISCOVER);
        assertThat(failed.reason()).contains("no metadata at any standard path");
    }

    @Test
    void onConnect_rejectsNonHttpScheme() throws Exception {
        AtomicReference<McpScannerTab> tabRef = new AtomicReference<>();

        invokeAndWait(() -> {
            McpScannerTab tab = newTab();
            tab.endpointFieldForTest().setText("ftp://x");
            tabRef.set(tab);
            clickButton(tab.primaryButtonForTest());
        });

        drainSwingEvents();

        UiConnectionState finalState = tabRef.get().stateForTest();
        assertThat(finalState).isInstanceOf(UiConnectionState.Failed.class);
        UiConnectionState.Failed failed = (UiConnectionState.Failed) finalState;
        assertThat(failed.phase()).isEqualTo(ConnectPhase.CONNECT);
        assertThat(failed.reason()).contains("http or https");
        verify(clientManager, never()).connect(any());
    }

    private static McpToolDefinition readOnlyTool(String name, String description) {
        ToolAnnotations readOnly = new ToolAnnotations(null, true, null, null, null);
        return new McpToolDefinition(name, description, "{}", List.of(), readOnly);
    }

    private static McpToolDefinition destructiveTool(String name) {
        ToolAnnotations destructive = new ToolAnnotations(null, false, true, null, null);
        return new McpToolDefinition(name, "", "{}", List.of(), destructive);
    }

    private static ConnectResult emptyConnectResult() {
        return new ConnectResult(
                List.<McpToolDefinition>of(),
                List.<McpResourceDefinition>of(),
                List.<McpResourceTemplateDefinition>of(),
                List.<McpPromptDefinition>of(),
                ServerMetadata.empty());
    }

    private static void clickButton(JButton button) {
        for (var listener : button.getActionListeners()) {
            listener.actionPerformed(new ActionEvent(button, ActionEvent.ACTION_PERFORMED, button.getActionCommand()));
        }
    }

    private static void drainSwingEvents() throws InterruptedException, InvocationTargetException {
        for (int i = 0; i < 20; i++) {
            invokeAndWait(() -> {});
            Thread.sleep(5);
        }
    }

    private static void invokeAndWait(Runnable r) throws InterruptedException, InvocationTargetException {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeAndWait(r);
        }
    }
}
