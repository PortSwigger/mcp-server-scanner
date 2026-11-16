package com.mcpscanner.ui;

import com.mcpscanner.config.AuthTypeNames;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.mcp.ToolAnnotations;
import com.mcpscanner.scan.OutcomeReportingScan;
import com.mcpscanner.scan.ScanActivity;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.scan.ScanOutcome;
import com.mcpscanner.scan.request.GeneratedScan;
import com.mcpscanner.testutil.SwingTree;
import com.mcpscanner.ui.widgets.UiStyle;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import javax.swing.JButton;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.Component;
import java.awt.Container;
import java.awt.event.KeyEvent;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static com.mcpscanner.ui.McpScannerTabFixture.ENDPOINT;
import static com.mcpscanner.ui.McpScannerTabFixture.oauthClient;
import static com.mcpscanner.ui.McpScannerTabFixture.awaitConnectLabel;
import static com.mcpscanner.ui.McpScannerTabFixture.click;
import static com.mcpscanner.ui.McpScannerTabFixture.connectButton;
import static com.mcpscanner.ui.McpScannerTabFixture.drawer;
import static com.mcpscanner.ui.McpScannerTabFixture.endpointField;
import static com.mcpscanner.ui.McpScannerTabFixture.find;
import static com.mcpscanner.ui.McpScannerTabFixture.flushEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.header;
import static com.mcpscanner.ui.McpScannerTabFixture.fromEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.onEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.scanBar;
import static com.mcpscanner.ui.McpScannerTabFixture.scanButton;
import static com.mcpscanner.ui.McpScannerTabFixture.serverConfig;
import static com.mcpscanner.ui.McpScannerTabFixture.statusText;
import static com.mcpscanner.ui.McpScannerTabFixture.tools;
import static com.mcpscanner.ui.McpScannerTabFixture.transportCombo;
import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class McpScannerTabUxTest {

    private static final McpToolDefinition UNANNOTATED = new McpToolDefinition("search", "Search", "{}");
    private static final McpToolDefinition READ_ONLY = new McpToolDefinition("read_file", "Read", "{}", List.of(),
            new ToolAnnotations(null, true, null, null, null));
    private static final McpResourceDefinition README = new McpResourceDefinition("docs://readme", "readme", "", "text/plain");
    private static final McpPromptDefinition PROMPT = new McpPromptDefinition("summarise", "", List.of());

    private McpScannerTabFixture fixture;

    @BeforeEach
    void setUp() {
        fixture = new McpScannerTabFixture();
        when(fixture.checkRegistry.enabledActiveCheckCount()).thenReturn(11L);
    }

    @Test
    void scanExplainsThatItNeedsAConnectionFirst() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();

            assertThat(scanButton(tab).isEnabled()).isFalse();
            assertThat(scanButton(tab).getToolTipText()).isEqualTo("Connect to an MCP server first");
        });
    }

    @Test
    void connectedScanWithNothingTickedSaysWhatToDoNextToTheButton() throws Exception {
        fixture.sendOnlyItemInvocations();
        McpScannerTab tab = fixture.connected(inventory(List.of(UNANNOTATED), List.of(), List.of()));
        onEdt(() -> {
            assertThat(scanButton(tab).isEnabled()).isFalse();
            assertThat(scanButton(tab).getToolTipText()).startsWith("Tick a tool");
            assertThat(scanBar(tab).scanHint().isVisible()).isTrue();
            assertThat(scanBar(tab).scanHint().getText()).isEqualTo("Tick items to scan");
        });
    }

    @Test
    void disabledConnectShowsItsReasonNextToTheButtons() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();
            fixture.useAuth(AuthTypeNames.BEARER);
            endpointField(tab).setText(ENDPOINT);

            assertThat(connectButton(tab).isEnabled()).isFalse();
            assertThat(header(tab).connectHint().getText()).isEqualTo("Enter a bearer token for User 1");
        });
    }

    @Test
    void cancelExplainsThatItStopsTheConnectionAttempt() throws Exception {
        CompletableFuture<Void> gate = new CompletableFuture<>();
        try {
            McpScannerTab tab = fixture.connecting(gate);
            onEdt(() -> {
                assertThat(connectButton(tab).getText()).isEqualTo("Cancel");
                assertThat(connectButton(tab).getToolTipText()).isEqualTo("Stop this connection attempt");
            });
        } finally {
            gate.complete(null);
        }
    }

    @Test
    void disconnectedScanSaysToConnectFirst() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();
            fixture.useAuth(AuthTypeNames.NONE);
            endpointField(tab).setText(ENDPOINT);

            assertThat(scanBar(tab).scanHint().getText()).isEqualTo("Connect, then tick items to scan");
        });
    }

    @Test
    void scanButtonAndTabTitlesCountWhatIsTicked() throws Exception {
        McpScannerTab tab = fixture.connected(inventory(List.of(READ_ONLY, UNANNOTATED), List.of(README), List.of(PROMPT)));
        onEdt(() -> {
            assertThat(scanButton(tab).getText()).isEqualTo("Scan 3 items");
            assertThat(scanButton(tab).getToolTipText())
                    .isEqualTo("Scan the 3 selected items (1 tool, 1 resource, 1 prompt) with "
                            + ScanModeText.of(ScanMode.MCP_ONLY).label());
            JTabbedPane tabs = find(tab, InventoryTabs.class);
            assertThat(List.of(tabs.getTitleAt(0), tabs.getTitleAt(1), tabs.getTitleAt(2), tabs.getTitleAt(3)))
                    .containsExactly("Tools (1/2)", "Resources (1/1)", "Templates (0)", "Prompts (1/1)");
            assertThat(scanBar(tab).scanHint().isVisible()).isFalse();
        });
    }

    @Test
    void scanStatusCountsEveryKindNotJustTools() throws Exception {
        McpScannerTab tab = fixture.connected(inventory(List.of(UNANNOTATED), List.of(README), List.of()));
        onEdt(() -> scanButton(tab).doClick());

        await().atMost(ofSeconds(5)).untilAsserted(() -> onEdt(() ->
                assertThat(statusText(tab))
                        .contains("Scan started: 1 item (1 resource)")
                        .contains("Target › Issues")
                        .doesNotContain("0 tools")));
    }

    @Test
    void scanRunsOnlyMcpChecksByDefaultAndSaysSo() throws Exception {
        McpScannerTab tab = fixture.connected(inventory(List.of(READ_ONLY), List.of(), List.of()));
        onEdt(() -> scanButton(tab).doClick());

        await().atMost(ofSeconds(5)).untilAsserted(() -> onEdt(() ->
                assertThat(statusText(tab)).isEqualTo(startedStatus(ScanMode.MCP_ONLY))));
        verify(fixture.scanLauncher).captureScan(eq(ScanMode.MCP_ONLY), anyString(), any(GeneratedScan.class), any(),
                any());
        assertThat(fixture.eventLog.snapshot()).anySatisfy(entry -> {
            assertThat(entry.message()).isEqualTo(startedLogLine(ScanMode.MCP_ONLY));
            assertThat(entry.kept()).isTrue();
        });
    }

    @Test
    void scanUsesTheModeChosenWhenItIsClicked() throws Exception {
        McpScannerTab tab = fixture.connected(inventory(List.of(READ_ONLY), List.of(), List.of()));
        fixture.scanModeSetting.select(ScanMode.MCP_AND_BURP);
        onEdt(() -> scanButton(tab).doClick());

        await().atMost(ofSeconds(5)).untilAsserted(() -> onEdt(() ->
                assertThat(statusText(tab)).isEqualTo(startedStatus(ScanMode.MCP_AND_BURP))));
        verify(fixture.scanLauncher).captureScan(eq(ScanMode.MCP_AND_BURP), anyString(), any(GeneratedScan.class),
                any(), any());
        assertThat(fixture.eventLog.snapshot()).anySatisfy(entry -> assertThat(entry.message())
                .isEqualTo(startedLogLine(ScanMode.MCP_AND_BURP)));
    }

    @Test
    void scanModeCanBeChosenBeforeConnecting() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();

            assertThat(scanButton(tab).isEnabled()).isFalse();
            assertThat(scanModeButton(tab).isEnabled()).isTrue();
        });
    }

    @Test
    void choosingBurpModeRelabelsTheScanBarAndLaunchesABurpAudit() throws Exception {
        McpScannerTab tab = fixture.connected(inventory(List.of(READ_ONLY), List.of(), List.of()));
        chooseMode(ScanMode.MCP_AND_BURP);

        onEdt(() -> {
            assertThat(scanModeButton(tab).getToolTipText()).isEqualTo(modeTooltip(ScanMode.MCP_AND_BURP));
            assertThat(scanButton(tab).getToolTipText())
                    .isEqualTo("Scan the 1 selected item (1 tool) with " + ScanModeText.of(ScanMode.MCP_AND_BURP).label());
            assertThat(scanBar(tab).checksSummary().getToolTipText()).isEqualTo(checksTooltip(ScanMode.MCP_AND_BURP));
            scanButton(tab).doClick();
        });

        await().atMost(ofSeconds(5)).untilAsserted(() -> verify(fixture.scanLauncher).captureScan(
                eq(ScanMode.MCP_AND_BURP), anyString(), any(GeneratedScan.class), any(), any()));
    }

    @Test
    void choosingMcpOnlyRelabelsTheScanBarAndLaunchesTheEngine() throws Exception {
        fixture.scanModeSetting.select(ScanMode.MCP_AND_BURP);
        McpScannerTab tab = fixture.connected(inventory(List.of(READ_ONLY), List.of(), List.of()));
        chooseMode(ScanMode.MCP_ONLY);

        onEdt(() -> {
            assertThat(scanModeButton(tab).getToolTipText()).isEqualTo(modeTooltip(ScanMode.MCP_ONLY));
            assertThat(scanBar(tab).checksSummary().getToolTipText()).isEqualTo(checksTooltip(ScanMode.MCP_ONLY));
            scanButton(tab).doClick();
        });

        await().atMost(ofSeconds(5)).untilAsserted(() -> verify(fixture.scanLauncher).captureScan(
                eq(ScanMode.MCP_ONLY), anyString(), any(GeneratedScan.class), any(), any()));
    }

    @Test
    void finishedScanReplacesTheStartedStatusWithItsIssueCount() throws Exception {
        AtomicReference<Consumer<ScanOutcome>> finish = new AtomicReference<>();
        OutcomeReportingScan running = mock(OutcomeReportingScan.class);
        doAnswer(call -> {
            finish.set(call.getArgument(0));
            return null;
        }).when(running).whenCompleted(any());
        when(fixture.scanLauncher.launchScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), anyMap()))
                .thenReturn(running);
        McpScannerTab tab = fixture.connected(inventory(List.of(READ_ONLY), List.of(), List.of()));
        onEdt(() -> scanButton(tab).doClick());
        await().atMost(ofSeconds(5)).until(() -> finish.get() != null);

        finish.get().accept(new ScanOutcome(11, false));

        await().atMost(ofSeconds(5)).untilAsserted(() -> onEdt(() ->
                assertThat(statusText(tab)).isEqualTo("Scan finished · 11 issues · Results in Target › Issues")));
    }

    @Test
    void failedScanLaunchNeverReportsSuccess() throws Exception {
        when(fixture.scanLauncher.launchScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), anyMap()))
                .thenThrow(new IllegalStateException("scanner unavailable"));
        McpScannerTab tab = fixture.connected(inventory(List.of(READ_ONLY), List.of(), List.of()));
        onEdt(() -> scanButton(tab).doClick());

        await().atMost(ofSeconds(5)).untilAsserted(() -> onEdt(() -> {
            assertThat(statusText(tab)).startsWith("Scan failed: scanner unavailable");
            assertThat(scanButton(tab).getText()).isEqualTo("Scan 1 item");
        }));
    }

    @Test
    void scanFinishingAfterDisconnectDoesNotOverwriteTheDisconnectedStatus() throws Exception {
        CompletableFuture<Void> release = new CompletableFuture<>();
        when(fixture.scanLauncher.launchScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), anyMap())).thenAnswer(call -> {
            release.get(5, TimeUnit.SECONDS);
            return null;
        });
        McpScannerTab tab = fixture.connected(inventory(List.of(READ_ONLY), List.of(), List.of()));
        onEdt(() -> {
            scanButton(tab).doClick();
            connectButton(tab).doClick();
        });

        release.complete(null);
        await().atMost(ofSeconds(5)).until(() -> fromEdt(() -> !scanButton(tab).getText()
                .equals(ScanLaunchPresenter.STARTING)));

        onEdt(() -> assertThat(statusText(tab)).isEqualTo("Disconnected"));
    }

    @Test
    void runningScansAreShownWithAStopControl() throws Exception {
        when(fixture.scanLauncher.activity()).thenReturn(ScanActivity.burpAudit(120, 2));
        McpScannerTab tab = fixture.connected(inventory(List.of(READ_ONLY), List.of(), List.of()));
        onEdt(() -> {
            ScanActivityPanel activity = find(tab, ScanActivityPanel.class);
            assertThat(activity.isVisible()).isTrue();
            assertThat(activity.summaryText()).isEqualTo("1 Burp audit · 120 requests · 2 issues");
            activity.stopButton().doClick();
        });

        verify(fixture.scanLauncher).cancelRunningScans();
    }

    @Test
    void terminalOAuthFailureFailsTheConnectionSoConnectReconnects() throws Exception {
        OAuthAuthCodeStrategy oauth = mock(OAuthAuthCodeStrategy.class);
        when(oauth.headers()).thenReturn(Map.of("Authorization", "Bearer token"));
        when(oauth.registrationMode()).thenReturn(Optional.empty());
        McpScannerTab tab = connectedWithOAuth(oauth);
        ArgumentCaptor<Runnable> terminalFailure = ArgumentCaptor.forClass(Runnable.class);
        verify(oauth).setTerminalFailureListener(terminalFailure.capture());

        terminalFailure.getValue().run();
        flushEdt();

        onEdt(() -> {
            assertThat(connectButton(tab).getText()).isEqualTo("Connect");
            assertThat(statusText(tab)).contains("token refresh rejected");
        });
        verify(fixture.scanLauncher).cancelRunningScans();
    }

    @Test
    void pressingEnterInTheEndpointFieldConnects() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();
            fixture.useAuth(AuthTypeNames.NONE);
            endpointField(tab).setText("ftp://mcp.example.com/mcp");

            endpointField(tab).postActionEvent();

            assertThat(statusText(tab)).isEqualTo("Connect failed: Endpoint must use http or https");
        });
    }

    @Test
    void connectAndScanHaveMnemonicsThatFollowTheLabel() throws Exception {
        McpScannerTab tab = fixture.connected(inventory(List.of(READ_ONLY), List.of(), List.of()));
        onEdt(() -> {
            assertThat(connectButton(tab).getMnemonic()).isEqualTo(KeyEvent.VK_D);
            assertThat(scanButton(tab).getMnemonic()).isEqualTo(KeyEvent.VK_S);
        });
    }

    @Test
    void connectIsThePrimaryActionUntilConnectedThenScanIs() throws Exception {
        McpScannerTab tab = fromEdt(fixture::newTab);
        onEdt(() -> {
            assertThat(connectButton(tab).isPrimary()).isTrue();
            assertThat(scanButton(tab).isPrimary()).isFalse();
        });

        fixture.connect(tab, inventory(List.of(), List.of(), List.of()));

        onEdt(() -> {
            assertThat(connectButton(tab).isPrimary()).isFalse();
            assertThat(scanButton(tab).getClientProperty(UiStyle.STYLE_CLASS)).isEqualTo(UiStyle.PRIMARY);
        });
    }

    @Test
    void checksSummaryShowsHowManyChecksRunAndOpensTheChecksPanel() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();

            assertThat(scanBar(tab).checksSummary().getText()).isEqualTo("11 MCP checks on");
            scanBar(tab).checksSummary().doClick();

            assertThat(drawer(tab).expandedSection()).contains(McpScannerTab.CHECKS_SECTION);
        });
    }

    @Test
    void checksAreOpenOnStartAndTheOtherSectionsAreRightHandTabs() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();

            assertThat(drawer(tab).expandedSection()).contains(McpScannerTab.CHECKS_SECTION);
            assertThat(drawer(tab).sectionOrder()).containsExactly(McpScannerTab.CHECKS_SECTION,
                    McpScannerTab.USERS_SECTION, McpScannerTab.CLIENT_SECTION, McpScannerTab.REQUESTS_SECTION,
                    McpScannerTab.LOG_SECTION, McpScannerTab.SETTINGS_SECTION);
            assertThat(drawer(tab).labelOf(McpScannerTab.USERS_SECTION)).isEqualTo("Users (1)");
            assertThat(SwingTree.visibleDescendants(tab)).contains(find(tab, InventoryTabs.class))
                    .doesNotContain(find(tab, LoggerPanel.class), oauthClient(tab));
        });
    }

    @Test
    void settingsAreReachableFromTheirOwnSideTab() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();
            AtomicBoolean opened = new AtomicBoolean();
            tab.setBurpSettingsOpener(() -> opened.set(true));

            drawer(tab).toggleFor(McpScannerTab.SETTINGS_SECTION).doClick();

            assertThat(drawer(tab).expandedSection()).contains(McpScannerTab.SETTINGS_SECTION);
            SettingsPanel settings = (SettingsPanel) SwingTree.visibleDescendants(tab).stream()
                    .filter(SettingsPanel.class::isInstance).findFirst().orElseThrow();
            settings.burpSettingsButtonForTest().doClick();
            assertThat(opened).isTrue();
        });
    }

    @Test
    void anErrorFlagsTheLogToggleUntilTheLogIsOpened() throws Exception {
        McpEventLog eventLog = new McpEventLog(null);
        fixture.eventLog = eventLog;
        McpScannerTab tab = fromEdt(fixture::newTab);

        eventLog.error("boom");
        await().atMost(ofSeconds(5)).until(() -> fromEdt(() ->
                drawer(tab).labelOf(McpScannerTab.LOG_SECTION).equals("Log ●")));

        onEdt(() -> {
            drawer(tab).toggleFor(McpScannerTab.LOG_SECTION).doClick();
            assertThat(drawer(tab).labelOf(McpScannerTab.LOG_SECTION)).isEqualTo("Log");
        });
    }

    @Test
    void theClientTabHoldsTheOAuthClientInAScrollingFormAndTheUsersTabDoesNot() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();

            drawer(tab).toggleFor(McpScannerTab.USERS_SECTION).doClick();
            assertThat(SwingTree.visibleDescendants(tab)).doesNotContain(oauthClient(tab));

            drawer(tab).toggleFor(McpScannerTab.CLIENT_SECTION).doClick();

            assertThat(SwingTree.visibleDescendants(tab)).contains(oauthClient(tab), serverConfig(tab),
                    find(tab, ClientIdentityPanel.class));
            assertThat(SwingTree.labelledField(serverConfig(tab), "Grant:")).isEmpty();
            assertThat(SwingUtilities.getAncestorOfClass(javax.swing.JScrollPane.class, serverConfig(tab)))
                    .isNotNull();
        });
    }

    @Test
    void theStripsIncompleteOAuthActionOpensTheClientTab() throws Exception {
        McpScannerTab tab = fromEdt(fixture::newTab);
        onEdt(() -> {
            header(tab).endpointField().setText("http://127.0.0.1:8765/mcp");
            fixture.useAuth(AuthTypeNames.OAUTH);
            serverConfig(tab).oauthConfig().getRegistrationModeSelector()
                    .setSelectedItem(com.mcpscanner.core.oauth.RegistrationMode.PRE_REGISTERED);
            serverConfig(tab).oauthConfig().getOauthClientIdField().setText("");
        });
        onEdt(() -> {
            javax.swing.JButton open = SwingTree.descendants(tab).stream()
                    .filter(javax.swing.JButton.class::isInstance).map(javax.swing.JButton.class::cast)
                    .filter(button -> "Open OAuth client".equals(button.getText()))
                    .findFirst().orElseThrow();

            open.doClick();

            assertThat(drawer(tab).expandedSection()).contains(McpScannerTab.CLIENT_SECTION);
        });
    }

    @Test
    void theOAuthClientLinkOpensTheClientTab() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();
            drawer(tab).toggleFor(McpScannerTab.USERS_SECTION).doClick();

            SwingTree.descendants(tab).stream()
                    .filter(com.mcpscanner.ui.widgets.HyperlinkLabel.class::isInstance)
                    .map(com.mcpscanner.ui.widgets.HyperlinkLabel.class::cast)
                    .filter(link -> link.getText().contains("OAuth client in the Client tab"))
                    .findFirst().orElseThrow().activate();

            assertThat(drawer(tab).expandedSection()).contains(McpScannerTab.CLIENT_SECTION);
        });
    }

    @Test
    void typingAnEndpointEnablesConnectWithoutLeavingTheField() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();
            header(tab).endpointField().setText("");
            assertThat(connectButton(tab).isEnabled()).isFalse();
            assertThat(header(tab).connectHint().getText()).isEqualTo("Enter the MCP endpoint URL");

            header(tab).endpointField().setText("http://127.0.0.1:8766/mcp");

            assertThat(connectButton(tab).isEnabled()).isTrue();
            assertThat(header(tab).connectHint().isVisible()).isFalse();
        });
    }

    @Test
    void theClientTabShowsHowTheExtensionPresentsItself() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();

            drawer(tab).toggleFor(McpScannerTab.CLIENT_SECTION).doClick();

            assertThat(SwingTree.visibleDescendants(tab)).contains(find(tab, ClientIdentityPanel.class));
        });
    }

    @Test
    void theHeaderOffersNoAuthSelectorBecauseCredentialsArePerUser() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();

            assertThat(SwingTree.descendants(header(tab))).filteredOn(javax.swing.JLabel.class::isInstance)
                    .extracting(label -> ((javax.swing.JLabel) label).getText()).doesNotContain("Auth:");
        });
    }

    @Test
    void connectedLocksOnlyTheOAuthClientAndItsDisconnectLinkEndsTheSession() throws Exception {
        McpScannerTab tab = fixture.connected(inventory(List.of(READ_ONLY), List.of(), List.of()));
        onEdt(() -> {
            assertThat(oauthClient(tab).showsLockNotice()).isTrue();
            assertThat(serverConfig(tab).oauthConfig().getOauthIssuerField().isEnabled()).isFalse();
            assertThat(SwingTree.descendants(find(tab, ClientIdentityPanel.class)))
                    .filteredOn(javax.swing.JTextField.class::isInstance)
                    .allMatch(java.awt.Component::isEnabled);

            SwingTree.descendants(oauthClient(tab)).stream()
                    .filter(com.mcpscanner.ui.widgets.HyperlinkLabel.class::isInstance)
                    .map(com.mcpscanner.ui.widgets.HyperlinkLabel.class::cast).findFirst().orElseThrow().activate();

            assertThat(statusText(tab)).isEqualTo("Disconnected");
            assertThat(oauthClient(tab).showsLockNotice()).isFalse();
            assertThat(serverConfig(tab).oauthConfig().getOauthIssuerField().isEnabled()).isTrue();
        });
    }

    @Test
    void at900PixelsEveryHeaderAndScanBarControlIsFullyVisibleAndTheInventoryKeepsTheSpace() throws Exception {
        McpScannerTab tab = fixture.connected(inventory(List.of(READ_ONLY), List.of(README), List.of()));
        onEdt(() -> {
            drawer(tab).collapse();
            tab.setSize(900, 700);
            layOut(tab);

            assertFullyVisible(tab, connectButton(tab));
            assertFullyVisible(tab, scanButton(tab));
            assertFullyVisible(tab, scanBar(tab).checksSummary());
            assertThat(endpointField(tab).getWidth()).isGreaterThanOrEqualTo(ConnectionHeader.ENDPOINT_FIELD_MIN_WIDTH);
            assertThat(find(tab, InventoryTabs.class).getWidth()).isGreaterThan(850);
            assertThat(find(tab, InventoryTabs.class).getHeight()).isGreaterThan(400);
        });
    }

    @Test
    void transportDropdownStaysCompactWhileTheEndpointTakesTheSlack() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();
            tab.setSize(1440, 800);
            layOut(tab);

            assertThat(transportCombo(tab).getWidth()).isEqualTo(transportCombo(tab).getPreferredSize().width);
            assertThat(endpointField(tab).getWidth()).isGreaterThan(900);
        });
    }

    @Test
    void sendToButtonFollowsTheConnectionState() throws Exception {
        when(fixture.clientManager.isConnected()).thenReturn(false);
        McpScannerTab tab = fixture.connected(inventory(List.of(READ_ONLY), List.of(), List.of()));
        onEdt(() -> {
            tab.setSendToDestinations(List.of(com.mcpscanner.ui.sendto.SendToDestination.of("Repeater", (r, t) -> { })));
            tools(tab).table().setRowSelectionInterval(0, 0);
            Component sendTo = sendToButton(tools(tab));
            assertThat(sendTo.isEnabled()).isFalse();

            when(fixture.clientManager.isConnected()).thenReturn(true);
            tools(tab).getTableModel().setValueAt(true, 0, 0);

            assertThat(sendTo.isEnabled()).isTrue();
        });
    }

    private McpScannerTab connectedWithOAuth(OAuthAuthCodeStrategy oauth) throws Exception {
        when(fixture.clientManager.connect(any())).thenReturn(inventory(List.of(READ_ONLY), List.of(), List.of()));
        McpScannerTab tab = fromEdt(() -> {
            OAuthConfigPanel oauthPanel = ServerConfigPanels.spiedOAuthPanel(fixture.configStore);
            oauthPanel.getOauthIssuerField().setText("https://issuer.example");
            doReturn(oauth).when(oauthPanel).completeOAuthDance(any(), any(), any(), any());
            McpScannerTab created = fixture.newTab(ServerConfigPanels.around(oauthPanel));
            endpointField(created).setText(ENDPOINT);
            fixture.useAuth(AuthTypeNames.OAUTH);
            click(connectButton(created));
            return created;
        });
        awaitConnectLabel(tab, "Disconnect");
        return tab;
    }

    private static ConnectResult inventory(List<McpToolDefinition> tools, List<McpResourceDefinition> resources,
                                           List<McpPromptDefinition> prompts) {
        return new ConnectResult(tools, resources, List.of(), prompts, ServerMetadata.empty());
    }

    private void chooseMode(ScanMode mode) throws Exception {
        fixture.scanModeSetting.select(mode);
        flushEdt();
    }

    private static JButton scanModeButton(McpScannerTab tab) {
        return SwingTree.descendants(tab).stream()
                .filter(component -> component instanceof JButton button
                        && button.getToolTipText() != null && button.getToolTipText().startsWith("Scan mode: "))
                .map(JButton.class::cast)
                .findFirst().orElseThrow();
    }

    private static String modeTooltip(ScanMode mode) {
        return ScanModeText.of(mode).tooltip();
    }

    private static String checksTooltip(ScanMode mode) {
        return "Scans run " + ScanModeText.of(mode).checksRun(11) + ". Click to review them.";
    }

    private static String startedStatus(ScanMode mode) {
        return "Scan started: 1 item (1 tool) · Results in " + ScanModeText.of(mode).resultsLocation();
    }

    private static String startedLogLine(ScanMode mode) {
        return "Scan started: 1 item (1 tool) with " + ScanModeText.of(mode).checksRun(11);
    }

    private static Component sendToButton(Container root) {
        return SwingTree.descendants(root).stream()
                .filter(component -> component instanceof javax.swing.JButton button
                        && button.getText().startsWith("Send to"))
                .findFirst().orElseThrow();
    }

    private static void assertFullyVisible(Container root, Component component) {
        java.awt.Rectangle bounds = SwingUtilities.convertRectangle(component.getParent(), component.getBounds(), root);
        assertThat(component.getWidth()).as(component + " width").isGreaterThanOrEqualTo(component.getPreferredSize().width);
        assertThat(bounds.x + bounds.width).as(component + " right edge").isLessThanOrEqualTo(root.getWidth());
    }

    private static void layOut(Container container) {
        container.doLayout();
        for (Component child : container.getComponents()) {
            if (child instanceof Container nested) {
                layOut(nested);
            }
        }
    }
}
