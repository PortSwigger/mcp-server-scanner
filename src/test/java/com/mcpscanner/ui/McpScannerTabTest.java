package com.mcpscanner.ui;

import org.junit.jupiter.params.provider.EnumSource;

import com.mcpscanner.config.AuthTypeNames;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.SignInEvidence;
import com.mcpscanner.auth.grants.ClientAuthenticationProviderRegistry;
import com.mcpscanner.auth.grants.EnterpriseIdentityProviderRegistry;
import com.mcpscanner.auth.grants.OptionalGrantAuthFactory;
import com.mcpscanner.auth.grants.OptionalGrantSettings;
import com.mcpscanner.identity.IdentityAuthKind;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.discovery.AuthRequirement;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.auth.oauth.discovery.DiscoveryFailedException;
import com.mcpscanner.auth.oauth.discovery.DiscoverySource;
import com.mcpscanner.auth.oauth.discovery.OAuthMetadataDiscoverer;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.scan.RunningScan;
import com.mcpscanner.scan.ScanActivity;
import com.mcpscanner.scan.ScanConnection;
import com.mcpscanner.scan.ScanInventory;
import com.mcpscanner.scan.ScanMode;
import com.mcpscanner.scan.request.GeneratedScan;
import com.mcpscanner.testutil.SwingTree;
import com.mcpscanner.testutil.TestOAuthFlows;
import com.mcpscanner.ui.state.ConnectPhase;
import com.mcpscanner.ui.state.ConnectionStatus;
import com.mcpscanner.core.oauth.RegistrationMode;
import org.awaitility.core.ConditionFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import com.mcpscanner.testutil.Polling;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import java.awt.BorderLayout;
import java.awt.Container;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Supplier;

import static com.mcpscanner.ui.McpScannerTabFixture.ENDPOINT;
import static com.mcpscanner.ui.McpScannerTabFixture.awaitConnectLabel;
import static com.mcpscanner.ui.McpScannerTabFixture.awaitStatus;
import static com.mcpscanner.ui.McpScannerTabFixture.click;
import static com.mcpscanner.ui.McpScannerTabFixture.connectButton;
import static com.mcpscanner.ui.McpScannerTabFixture.destructiveTool;
import static com.mcpscanner.ui.McpScannerTabFixture.emptyInventory;
import static com.mcpscanner.ui.McpScannerTabFixture.endpointField;
import static com.mcpscanner.ui.McpScannerTabFixture.fillGrant;
import static com.mcpscanner.ui.McpScannerTabFixture.find;
import static com.mcpscanner.ui.McpScannerTabFixture.inventory;
import static com.mcpscanner.ui.McpScannerTabFixture.fromEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.onEdt;
import static com.mcpscanner.ui.McpScannerTabFixture.prompts;
import static com.mcpscanner.ui.McpScannerTabFixture.readOnlyTool;
import static com.mcpscanner.ui.McpScannerTabFixture.resources;
import static com.mcpscanner.ui.McpScannerTabFixture.scanButton;
import static com.mcpscanner.ui.McpScannerTabFixture.statusText;
import static com.mcpscanner.ui.McpScannerTabFixture.templates;
import static com.mcpscanner.ui.McpScannerTabFixture.tools;
import static com.mcpscanner.ui.McpScannerTabFixture.transportCombo;
import static java.time.Duration.ofMillis;
import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.endsWith;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class McpScannerTabTest {

    private McpScannerTabFixture fixture;

    @BeforeEach
    void setUp() {
        fixture = new McpScannerTabFixture();
    }

    @ParameterizedTest
    @ValueSource(strings = {"CLIENT_CREDENTIALS", "ENTERPRISE_MANAGED", "Bearer Token", "AUTHORIZATION_CODE"})
    void connectingLocksConfigurationAndScanUsesConnectionCredentialsDespiteProgrammaticSelectionChanges(
            String selection) throws Exception {
        boolean optionalGrant = grantProfile(selection).isPresent();
        var entered = new AtomicBoolean();
        var release = new CompletableFuture<Void>();
        var expectedRef = new AtomicReference<AuthStrategy>();
        var launchedHeaders = new AtomicReference<Map<String, String>>();
        doAnswer(call -> {
            launchedHeaders.set(call.getArgument(3));
            return null;
        }).when(fixture.scanLauncher).launchScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), anyMap());
        when(fixture.clientManager.connect(any())).thenAnswer(call -> {
            expectedRef.set(((McpServerConfig) call.getArgument(0)).auth());
            if (!optionalGrant) {
                entered.set(true);
                release.join();
            }
            return inventory(List.of(readOnlyTool("echo")));
        });
        fixture.optionalGrants = (endpoint, settings) -> {
            entered.set(true);
            release.join();
            return () -> Map.of("Authorization", "Bearer grant-token");
        };
        try {
            var panelRef = new AtomicReference<ServerConfigPanel>();
            McpScannerTab tab = fromEdt(() -> {
                var oauthPanel = ServerConfigPanels.spiedOAuthPanel(fixture.configStore);
                var panel = panelWithEnterpriseProvider(oauthPanel);
                oauthPanel.getOauthIssuerField().setText("https://issuer.example");
                var oauth = mock(OAuthAuthCodeStrategy.class);
                when(oauth.headers()).thenReturn(Map.of("Authorization", "Bearer oauth-token"));
                doReturn(oauth).when(oauthPanel).completeOAuthDance(any(), any(), any(), any());
                var created = fixture.newTab(panel);
                endpointField(created).setText(ENDPOINT);
                selectAuth(panel, selection);
                grantProfile(selection).ifPresent(profile -> fillGrant(panel, profile, "client", "secret"));
                panelRef.set(panel);
                click(connectButton(created));
                return created;
            });
            await().atMost(ofSeconds(5)).untilTrue(entered);
            onEdt(() -> {
                assertThat(transportCombo(tab).isEnabled()).isFalse();
                assertThat(endpointField(tab).isEnabled()).isFalse();
                assertThat(connectButton(tab).isEnabled()).isTrue();
                fixture.identities.setCredential(fixture.identities.primaryUser().id(),
                        new BearerTokenAuthStrategy("changed-token"));
            });
            release.complete(null);
            awaitConnectLabel(tab, "Disconnect");
            onEdt(() -> click(scanButton(tab)));
            await().atMost(ofSeconds(5)).untilAsserted(() -> assertThat(launchedHeaders.get()).isNotNull());
            assertThat(fixture.authHolder.get()).isSameAs(expectedRef.get());
            assertThat(launchedHeaders.get()).containsAllEntriesOf(expectedRef.get().headers());
            onEdt(() -> click(connectButton(tab)));
            assertThat(fixture.authHolder.get()).isInstanceOf(NoAuthStrategy.class);
        } finally {
            release.complete(null);
        }
    }

    private ServerConfigPanel panelWithEnterpriseProvider() {
        var oauth = new OAuthConfigPanel(TestOAuthFlows.recording(), new OAuthDiscoveryPresenter(
                mock(OAuthMetadataDiscoverer.class)), TestDialogOwners.withoutSuiteFrame());
        oauth.bindConfigStore(fixture.configStore);
        return panelWithEnterpriseProvider(oauth);
    }

    private static ServerConfigPanel panelWithEnterpriseProvider(OAuthConfigPanel oauth) {
        return new ServerConfigPanel(oauth, new ClientAuthenticationProviderRegistry(List.of()),
                new EnterpriseIdentityProviderRegistry(Map.of("company", request -> null)));
    }

    private static java.util.Optional<OptionalGrantSettings.Profile> grantProfile(String selection) {
        return java.util.Arrays.stream(OptionalGrantSettings.Profile.values())
                .filter(profile -> profile.name().equals(selection)).findFirst();
    }

    private void selectAuth(ServerConfigPanel panel, String selection) {
        java.util.Optional<OptionalGrantSettings.Profile> grant = grantProfile(selection);
        if (grant.isPresent()) {
            fixture.identities.update(fixture.identities.primaryUser().withAuthKind(
                    grant.get() == OptionalGrantSettings.Profile.CLIENT_CREDENTIALS
                            ? IdentityAuthKind.OAUTH_CLIENT_CREDENTIALS : IdentityAuthKind.OAUTH_ENTERPRISE_MANAGED));
        } else if (selection.equals("AUTHORIZATION_CODE")) {
            fixture.useAuth(AuthTypeNames.OAUTH);
        } else {
            fixture.useAuth(selection);
            fixture.identities.setCredential(fixture.identities.primaryUser().id(),
                    new BearerTokenAuthStrategy("manual-token"));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"CLIENT_CREDENTIALS", "ENTERPRISE_MANAGED"})
    void selectedOptionalGrantObtainsCredentialsOffEdtAndKeepsThemForScanningWithoutPersistingSecrets(
            String selection) throws Exception {
        var settingsRef = new AtomicReference<OptionalGrantSettings>();
        var backend = mock(OptionalGrantAuthFactory.class);
        AuthStrategy credentials = () -> Map.of("Authorization", "Bearer machine-token");
        when(backend.create(any(), any())).thenAnswer(call -> {
            assertThat(SwingUtilities.isEventDispatchThread()).isFalse();
            settingsRef.set(call.getArgument(1));
            return credentials;
        });
        when(fixture.clientManager.connect(any())).thenReturn(emptyInventory());
        fixture.optionalGrants = backend::create;
        var panel = fromEdt(this::panelWithEnterpriseProvider);
        McpScannerTab tab = fromEdt(() -> {
            var created = fixture.newTab(panel);
            endpointField(created).setText(ENDPOINT);
            selectAuth(panel, selection);
            fillGrant(panel, grantProfile(selection).orElseThrow(), "machine-client", "ephemeral-secret");
            click(connectButton(created));
            return created;
        });
        awaitConnectLabel(tab, "Disconnect");
        assertThat(fixture.authHolder.get()).isSameAs(credentials);
        assertThat(settingsRef.get().expectedIssuer()).isEqualTo(URI.create("https://issuer.example"));
        assertThat(settingsRef.get().clientId()).isEqualTo("machine-client");
        assertThat(settingsRef.get().clientSecret()).isEqualTo("ephemeral-secret");
        verify(fixture.store, never()).setString(anyString(), contains("ephemeral-secret"));
        verify(fixture.store, never()).setString(anyString(), contains("machine-token"));
        onEdt(() -> click(connectButton(tab)));
        assertThat(fixture.authHolder.get()).isNotSameAs(credentials);
    }

    @Test
    void newInstallDefaultsToAutoWithVersionLabelledTransportChoices() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();

            assertThat(transportCombo(tab).getSelectedItem()).isEqualTo(TransportType.AUTO);
            assertThat(TransportType.values()).extracting(Object::toString).containsExactly(
                    "Auto", "HTTP 2026-07-28", "HTTP 2025 (session)", "SSE 2024-11-05");
        });
    }

    @Test
    void headerShowsNoExplanatoryTextAreasUntilACredentialIsNeeded() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();

            assertThat(SwingTree.visibleDescendants(headerOf(tab))).noneMatch(JTextArea.class::isInstance);
        });
    }

    private static Container headerOf(McpScannerTab tab) {
        return (Container) ((BorderLayout) tab.getLayout()).getLayoutComponent(BorderLayout.NORTH);
    }

    @Test
    void endpointFieldKeepsUsableWidthWhenToolbarIsSqueezed() throws Exception {
        onEdt(() -> assertThat(endpointField(fixture.newTab()).getMinimumSize().width).isGreaterThanOrEqualTo(280));
    }

    @Test
    void savedLegacyTransportIsRestoredAndNewChoiceIsPersistedByEnumName() throws Exception {
        when(fixture.store.getString("mcp.transport")).thenReturn("STREAMABLE_HTTP");

        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();

            assertThat(transportCombo(tab).getSelectedItem()).isEqualTo(TransportType.STREAMABLE_HTTP);
            transportCombo(tab).setSelectedItem(TransportType.MODERN_HTTP);
        });

        verify(fixture.store).setString("mcp.transport", "MODERN_HTTP");
    }

    @Test
    void savedSseTransportIsRestored() throws Exception {
        when(fixture.store.getString("mcp.transport")).thenReturn("SSE");

        onEdt(() -> assertThat(transportCombo(fixture.newTab()).getSelectedItem()).isEqualTo(TransportType.SSE));
    }

    @Test
    void connectedStatusUsesResolvedTransportAndNegotiatedVersion() throws Exception {
        when(fixture.session.transportType()).thenReturn(TransportType.SSE);
        when(fixture.session.negotiatedProtocolVersion()).thenReturn("2025-03-26");

        McpScannerTab tab = fixture.connected(emptyInventory());

        onEdt(() -> {
            assertThat(statusText(tab)).contains("SSE", "MCP 2025-03-26", "Auth: None").doesNotContain("Auto");
            assertThat(InfoSections.titled(find(tab, ServerInfoPanel.class), "Session").getText())
                    .contains("Requested mode: Auto", "Connected via: SSE", "MCP version: 2025-03-26",
                            "Endpoint: https://mcp.example.com/mcp");
            assertThat(InfoSections.titled(find(tab, ServerInfoPanel.class), "Authentication").getText())
                    .contains("Connected as: User 1 (primary user)", "Method: None");
        });

        onEdt(() -> click(connectButton(tab)));

        onEdt(() -> {
            assertThat(InfoSections.titled(find(tab, ServerInfoPanel.class), "Session").getText())
                    .contains("Not connected");
            assertThat(InfoSections.titled(find(tab, ServerInfoPanel.class), "Authentication").isVisible())
                    .isFalse();
        });
    }

    @Test
    void connectedStatusShowsSelectedOAuthAuthenticationMethod() throws Exception {
        when(fixture.clientManager.connect(any())).thenReturn(emptyInventory());
        when(fixture.session.transportType()).thenReturn(TransportType.MODERN_HTTP);
        when(fixture.session.negotiatedProtocolVersion()).thenReturn("2025-11-25");

        McpScannerTab tab = fromEdt(() -> {
            var oauthPanel = ServerConfigPanels.spiedOAuthPanel(fixture.configStore);
            var panel = ServerConfigPanels.around(oauthPanel);
            oauthPanel.getOauthIssuerField().setText("https://issuer.example");
            var oauth = mock(OAuthAuthCodeStrategy.class);
            when(oauth.headers()).thenReturn(Map.of("Authorization", "Bearer oauth-token"));
            when(oauth.registrationMode()).thenReturn(Optional.empty());
            var oauthStatus = ConnectionStatus.connected(null, "mcp.example.com", null, 0)
                    .withRegistrationMode(RegistrationMode.CIMD);
            doReturn(oauthStatus).when(oauthPanel).buildConnectedStatus(anyString(), anyInt());
            doReturn(oauth).when(oauthPanel).completeOAuthDance(any(), any(), any(), any());
            var created = fixture.newTab(panel);
            endpointField(created).setText(ENDPOINT);
            fixture.useAuth(AuthTypeNames.OAUTH);
            click(connectButton(created));
            return created;
        });

        awaitConnectLabel(tab, "Disconnect");

        onEdt(() -> {
            assertThat(statusText(tab))
                    .contains("Auth: OAuth 2.1", "OAuth client: CIMD", "HTTP 2026-07-28", "MCP 2025-11-25");
            assertThat(InfoSections.titled(find(tab, ServerInfoPanel.class), "Authentication").getText())
                    .contains("Method: OAuth 2.1 · Authorization code", "Token expires: Not reported");
        });
    }

    @Test
    void scanCapturesConnectionProvenanceBeforeStartingBackgroundWork() throws Exception {
        McpScannerTab tab = fixture.connectedWithAuth(() -> Map.of("Authorization", "Bearer A"),
                inventory(List.of(readOnlyTool("echo"))));
        var launched = new CompletableFuture<Map<String, String>>();
        var captured = new AtomicBoolean();
        when(fixture.scanLauncher.captureConnection()).thenAnswer(call -> {
            assertThat(SwingUtilities.isEventDispatchThread()).isTrue();
            captured.set(true);
            return ScanConnection.unbound(ignored -> Map.of());
        });
        when(fixture.session.scannerHeaders()).thenAnswer(call -> {
            assertThat(captured.get()).isTrue();
            return Map.of();
        });
        when(fixture.scanLauncher.captureScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), any(), any()))
                .thenAnswer(call -> {
                    assertThat(SwingUtilities.isEventDispatchThread()).isTrue();
                    Supplier<Map<String, String>> additional = call.getArgument(3);
                    return (Supplier<RunningScan>) () -> {
                        assertThat(additional.get()).containsEntry("Authorization", "Bearer A");
                        return fixture.scanLauncher.launchScan(ScanMode.MCP_ONLY, ENDPOINT,
                                new GeneratedScan(List.of(), List.of()),
                                Map.of("X-Mcp-Scanner-Audit-Capability", "connection-A"));
                    };
                });
        doAnswer(call -> {
            launched.complete(call.getArgument(3));
            return null;
        }).when(fixture.scanLauncher).launchScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), anyMap());

        onEdt(() -> click(scanButton(tab)));

        awaitSignal().until(launched::isDone);
        assertThat(launched.join()).containsEntry("X-Mcp-Scanner-Audit-Capability", "connection-A");
    }

    @Test
    void expiredOAuthHeadersAreAcquiredOffTheEventDispatchThread() throws Exception {
        var scanning = new AtomicBoolean();
        McpScannerTab tab = fixture.connectedWithAuth(() -> {
            assertThat(scanning.get() && SwingUtilities.isEventDispatchThread()).isFalse();
            return Map.of("Authorization", "Bearer refreshed");
        }, inventory(List.of(readOnlyTool("echo"))));
        var refreshed = new AtomicBoolean();
        when(fixture.session.scannerHeaders()).thenAnswer(call -> {
            assertThat(SwingUtilities.isEventDispatchThread()).isFalse();
            refreshed.set(true);
            return Map.of("Authorization", "Bearer refreshed");
        });
        scanning.set(true);

        onEdt(() -> click(scanButton(tab)));

        await().atMost(ofSeconds(5)).untilTrue(refreshed);
        await().atMost(ofSeconds(5)).untilAsserted(() ->
                verify(fixture.scanLauncher).launchScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), anyMap()));
    }

    @Test
    void scanPublishesCurrentAuthStrategyBeforeLaunch() throws Exception {
        AuthStrategy customStrategy = Map::of;
        McpScannerTab tab = fixture.connectedWithAuth(customStrategy, inventory(List.of(readOnlyTool("echo"))));
        fixture.authHolder.clear();
        AtomicBoolean launched = new AtomicBoolean();
        AtomicReference<AuthStrategy> publishedAtLaunch = new AtomicReference<>();
        doAnswer(inv -> {
            publishedAtLaunch.set(fixture.authHolder.get());
            launched.set(true);
            return null;
        }).when(fixture.scanLauncher).launchScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), anyMap());

        onEdt(() -> click(scanButton(tab)));

        awaitSignal().untilTrue(launched);
        assertThat(publishedAtLaunch.get()).isSameAs(customStrategy);
        assertThat(fixture.authHolder.get()).isSameAs(customStrategy);
    }

    @Test
    void scanLaunchGeneratesTheRequestsOfTheSelectedInventory() throws Exception {
        McpToolDefinition selectedTool = readOnlyTool("echo");
        McpScannerTab tab = fixture.connected(inventory(List.of(selectedTool)));
        AtomicBoolean launched = new AtomicBoolean();
        AtomicReference<GeneratedScan> generated = new AtomicReference<>();
        doAnswer(inv -> {
            generated.set(inv.getArgument(2));
            launched.set(true);
            return null;
        }).when(fixture.scanLauncher).launchScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), anyMap());

        onEdt(() -> click(scanButton(tab)));

        awaitSignal().untilTrue(launched);
        assertThat(generated.get().invokedTools()).containsExactly(selectedTool);
        assertThat(generated.get().messages()).extracting(com.mcpscanner.scan.request.ScanMessage::subject)
                .contains("tools/call echo", "tools/list");
    }

    @Test
    void onScanInvokesAuthStrategyHeadersOffEdt() throws Exception {
        AtomicReference<Boolean> capturedEdtFlag = new AtomicReference<>();
        McpScannerTab tab = fixture.connectedWithAuth(() -> {
            capturedEdtFlag.set(SwingUtilities.isEventDispatchThread());
            return Map.of();
        }, inventory(List.of(readOnlyTool("echo"))));

        onEdt(() -> click(scanButton(tab)));

        await().atMost(ofSeconds(5)).untilAsserted(() ->
                verify(fixture.scanLauncher).launchScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), anyMap()));
        assertThat(capturedEdtFlag.get()).isFalse();
    }

    @Test
    void onScanPassesOnlySelectedItemsToLauncher() throws Exception {
        McpToolDefinition toolKept = readOnlyTool("kept-tool");
        McpToolDefinition toolSkipped = readOnlyTool("skipped-tool");
        McpResourceDefinition resKept = new McpResourceDefinition("docs://keep", "k", "", "text/plain");
        McpResourceDefinition resSkipped = new McpResourceDefinition("docs://drop", "d", "", "text/plain");
        McpResourceTemplateDefinition tplKept = new McpResourceTemplateDefinition(
                "tmpl://keep/{x}", "tk", "", "text/plain");
        McpResourceTemplateDefinition tplSkipped = new McpResourceTemplateDefinition(
                "tmpl://drop/{x}", "td", "", "text/plain");
        McpPromptDefinition promptKept = new McpPromptDefinition("pkeep", "", List.of());
        McpPromptDefinition promptSkipped = new McpPromptDefinition("pdrop", "", List.of());
        McpScannerTab tab = fixture.connected(new ConnectResult(List.of(toolKept, toolSkipped),
                List.of(resKept, resSkipped), List.of(tplKept, tplSkipped), List.of(promptKept, promptSkipped),
                ServerMetadata.empty()));
        AtomicBoolean launched = new AtomicBoolean();
        AtomicReference<GeneratedScan> captured = new AtomicReference<>();
        doAnswer(inv -> {
            captured.set(inv.getArgument(2));
            launched.set(true);
            return null;
        }).when(fixture.scanLauncher).launchScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), anyMap());

        onEdt(() -> {
            resources(tab).getTableModel().setValueAt(false, 1, 0);
            templates(tab).getTableModel().setValueAt(false, 1, 0);
            prompts(tab).getTableModel().setValueAt(false, 1, 0);
            tools(tab).getTableModel().setValueAt(false, 1, 0);
            click(scanButton(tab));
        });

        awaitSignal().untilTrue(launched);
        List<String> subjects = captured.get().messages().stream()
                .map(com.mcpscanner.scan.request.ScanMessage::subject).toList();
        assertThat(captured.get().invokedTools()).containsExactly(toolKept);
        assertThat(subjects).contains("tools/call " + toolKept.name(), "resources/read " + resKept.uri(),
                        "prompts/get pkeep")
                .noneMatch(subject -> subject.contains(toolSkipped.name()) || subject.contains(resSkipped.uri())
                        || subject.contains("pdrop") || subject.contains("tmpl://drop"))
                .anyMatch(subject -> subject.startsWith("resources/read tmpl://keep/"));
    }

    @Test
    void scanButtonEnabledWhenOnlyResourcesSelected() throws Exception {
        McpScannerTab tab = fixture.connected(new ConnectResult(List.of(),
                List.of(new McpResourceDefinition("docs://keep", "k", "", "text/plain")),
                List.of(), List.of(), ServerMetadata.empty()));

        assertThat(fromEdt(() -> scanButton(tab).isEnabled())).isTrue();
    }

    @Test
    void scanButtonEnabledWhenOnlyResourceTemplatesSelected() throws Exception {
        McpScannerTab tab = fixture.connected(new ConnectResult(List.of(), List.of(),
                List.of(new McpResourceTemplateDefinition("tmpl://keep/{x}", "tk", "", "text/plain")),
                List.of(), ServerMetadata.empty()));

        assertThat(fromEdt(() -> scanButton(tab).isEnabled())).isTrue();
    }

    @Test
    void scanButtonEnabledWhenOnlyPromptsSelected() throws Exception {
        McpScannerTab tab = fixture.connected(new ConnectResult(List.of(), List.of(), List.of(),
                List.of(new McpPromptDefinition("pkeep", "", List.of())), ServerMetadata.empty()));

        assertThat(fromEdt(() -> scanButton(tab).isEnabled())).isTrue();
    }

    @Test
    void scanButtonDisabledWhenAllPanelsHaveNoSelections() throws Exception {
        fixture.sendOnlyItemInvocations();
        McpScannerTab tab = fixture.connected(new ConnectResult(
                List.of(new McpToolDefinition("echo", "", "{}")),
                List.of(new McpResourceDefinition("docs://drop", "d", "", "text/plain")),
                List.of(new McpResourceTemplateDefinition("tmpl://drop/{x}", "td", "", "text/plain")),
                List.of(new McpPromptDefinition("pdrop", "", List.of())), ServerMetadata.empty()));

        onEdt(() -> {
            tools(tab).getTableModel().setValueAt(false, 0, 0);
            resources(tab).getTableModel().setValueAt(false, 0, 0);
            templates(tab).getTableModel().setValueAt(false, 0, 0);
            prompts(tab).getTableModel().setValueAt(false, 0, 0);
            assertThat(scanButton(tab).isEnabled()).isFalse();
        });
    }

    @Test
    void scanButtonTogglesAsResourceSelectionsChange() throws Exception {
        fixture.sendOnlyItemInvocations();
        McpScannerTab tab = fixture.connected(new ConnectResult(List.of(),
                List.of(new McpResourceDefinition("docs://keep", "k", "", "text/plain")),
                List.of(), List.of(), ServerMetadata.empty()));

        assertThat(fromEdt(() -> scanButton(tab).isEnabled())).isTrue();
        onEdt(() -> resources(tab).getTableModel().setValueAt(false, 0, 0));
        assertThat(fromEdt(() -> scanButton(tab).isEnabled())).isFalse();
        onEdt(() -> resources(tab).getTableModel().setValueAt(true, 0, 0));
        assertThat(fromEdt(() -> scanButton(tab).isEnabled())).isTrue();
    }

    @Test
    void onDisconnectInvokesClientManagerDisconnectOffEdt() throws Exception {
        AtomicReference<Boolean> capturedEdtFlag = new AtomicReference<>();
        AtomicBoolean disconnectInvoked = new AtomicBoolean();
        doAnswer(inv -> {
            capturedEdtFlag.set(SwingUtilities.isEventDispatchThread());
            disconnectInvoked.set(true);
            return null;
        }).when(fixture.clientManager).disconnect();
        McpScannerTab tab = fixture.connected(emptyInventory());

        onEdt(() -> click(connectButton(tab)));

        awaitSignal().untilTrue(disconnectInvoked);
        assertThat(capturedEdtFlag.get()).isFalse();
    }

    @Test
    void disconnectFailureIsLoggedToErrorStream() throws Exception {
        doThrow(new RuntimeException("disconnect boom")).when(fixture.clientManager).disconnect();
        McpScannerTab tab = fixture.connected(emptyInventory());

        onEdt(() -> click(connectButton(tab)));

        await().atMost(ofSeconds(5)).untilAsserted(() ->
                verify(fixture.logging).logToError(contains("disconnect boom")));
    }

    @Test
    void shutdownCancelsActiveScans() throws Exception {
        McpScannerTab tab = fromEdt(fixture::newTab);

        tab.shutdown();

        verify(fixture.scanLauncher).cancelRunningScans();
    }

    @Test
    void shutdownUnsubscribesEveryEventLogListenerTheTabRegistered() throws Exception {
        fixture.eventLog = spy(new McpEventLog(null));
        McpScannerTab tab = fromEdt(fixture::newTab);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Consumer<McpEventLog.LogEntry>> subscribed = ArgumentCaptor.forClass(Consumer.class);
        verify(fixture.eventLog, atLeastOnce()).subscribe(subscribed.capture());

        onEdt(tab::shutdown);

        subscribed.getAllValues().forEach(listener -> verify(fixture.eventLog).unsubscribe(listener));
    }

    @Test
    void shutdownRemovesEveryCheckSettingsAndDisconnectListener() throws Exception {
        McpScannerTab tab = fromEdt(fixture::newTab);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<BiConsumer<String, Boolean>> settingsListeners = ArgumentCaptor.forClass(BiConsumer.class);
        ArgumentCaptor<Runnable> disconnectListeners = ArgumentCaptor.forClass(Runnable.class);
        verify(fixture.checkSettings, atLeastOnce()).addListener(settingsListeners.capture());
        verify(fixture.clientManager).addDisconnectListener(disconnectListeners.capture());

        onEdt(tab::shutdown);

        settingsListeners.getAllValues().forEach(listener -> verify(fixture.checkSettings).removeListener(listener));
        verify(fixture.clientManager).removeDisconnectListener(disconnectListeners.getValue());
    }

    @Test
    void theTabIsTheOnlyScanModeSubscriberAndShutdownRemovesIt() throws Exception {
        McpScannerTab tab = fromEdt(fixture::newTab);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Consumer<ScanMode>> modeListener = ArgumentCaptor.forClass(Consumer.class);
        verify(fixture.scanModeSetting).addListener(modeListener.capture());

        onEdt(tab::shutdown);

        verify(fixture.scanModeSetting).removeListener(modeListener.getValue());
    }

    @Test
    void shutdownStopsTheScanActivityPoller() throws Exception {
        when(fixture.scanLauncher.activity()).thenReturn(ScanActivity.burpAudit(1, 0));
        McpScannerTab tab = fromEdt(fixture::newTab);
        ScanActivityPanel activity = find(tab, ScanActivityPanel.class);
        assertThat(fromEdt(activity::isPolling)).isTrue();

        onEdt(tab::shutdown);

        assertThat(activity.isPolling()).isFalse();
    }

    @Test
    void onCancelDispatchesDisconnectOffEdt() throws Exception {
        AtomicReference<Boolean> capturedEdtFlag = new AtomicReference<>();
        AtomicBoolean disconnectStarted = new AtomicBoolean();
        CountDownLatch disconnectMayProceed = new CountDownLatch(1);
        doAnswer(inv -> {
            capturedEdtFlag.set(SwingUtilities.isEventDispatchThread());
            disconnectStarted.set(true);
            disconnectMayProceed.await(5, TimeUnit.SECONDS);
            return null;
        }).when(fixture.clientManager).disconnect();
        CompletableFuture<Void> gate = new CompletableFuture<>();
        try {
            McpScannerTab tab = fixture.connecting(gate);

            onEdt(() -> click(connectButton(tab)));

            awaitSignal().untilTrue(disconnectStarted);
            AtomicBoolean edtRanWhileDisconnecting = new AtomicBoolean(false);
            SwingUtilities.invokeLater(() -> edtRanWhileDisconnecting.set(true));
            await().atMost(ofSeconds(2)).pollInterval(ofMillis(10)).untilTrue(edtRanWhileDisconnecting);
            disconnectMayProceed.countDown();
            assertThat(capturedEdtFlag.get()).isFalse();
        } finally {
            gate.complete(null);
        }
    }

    @Test
    void onScanSkipsModalWhenAllSelectedToolsAreReadOnly() throws Exception {
        AtomicBoolean promptInvoked = new AtomicBoolean(false);
        fixture.scanPrompt = (parent, tools, count, invoker) -> {
            promptInvoked.set(true);
            return new DestructiveScanConfirmation.Result(false, false);
        };
        McpScannerTab tab = fixture.connected(inventory(List.of(readOnlyTool("safe"))));

        onEdt(() -> click(scanButton(tab)));

        awaitLaunches(1);
        assertThat(promptInvoked).isFalse();
    }

    @Test
    void onScanSkipsModalWhenDontAskAgainIsSet() throws Exception {
        when(fixture.store.getBoolean(anyString())).thenAnswer(invocation -> {
            String key = invocation.getArgument(0);
            return key.endsWith(".dontAskAgain") ? Boolean.TRUE : null;
        });
        AtomicBoolean promptInvoked = new AtomicBoolean(false);
        fixture.scanPrompt = (parent, tools, count, invoker) -> {
            promptInvoked.set(true);
            return new DestructiveScanConfirmation.Result(false, false);
        };
        McpScannerTab tab = fixture.connected(inventory(List.of(destructiveTool("destroy"))));

        tickFirstToolAndScan(tab);

        awaitLaunches(1);
        assertThat(promptInvoked).isFalse();
    }

    @Test
    void cancellingTheDestructiveScanConfirmationLeavesTheScanAuthUnpublished() throws Exception {
        AuthStrategy scanAuth = Map::of;
        fixture.scanPrompt = (parent, tools, count, invoker) -> new DestructiveScanConfirmation.Result(false, false);
        McpScannerTab tab = fixture.connectedWithAuth(scanAuth, inventory(List.of(destructiveTool("destroy"))));
        fixture.authHolder.clear();

        tickFirstToolAndScan(tab);

        assertThat(fixture.authHolder.get()).isNotSameAs(scanAuth);
    }

    @Test
    void onScanShowsModalAndProceedsWhenUserConfirms() throws Exception {
        AtomicBoolean promptInvoked = new AtomicBoolean(false);
        fixture.scanPrompt = (parent, tools, count, invoker) -> {
            promptInvoked.set(true);
            return new DestructiveScanConfirmation.Result(true, false);
        };
        McpScannerTab tab = fixture.connected(inventory(List.of(destructiveTool("destroy"))));

        tickFirstToolAndScan(tab);

        awaitLaunches(1);
        assertThat(promptInvoked).isTrue();
    }

    @ParameterizedTest
    @EnumSource(ScanMode.class)
    void theDestructiveScanConfirmationNamesWhatTheSelectedModeRuns(ScanMode mode) throws Exception {
        AtomicReference<String> askedInvoker = new AtomicReference<>();
        fixture.scanModeSetting.select(mode);
        fixture.scanPrompt = (parent, tools, count, invoker) -> {
            askedInvoker.set(invoker);
            return new DestructiveScanConfirmation.Result(false, false);
        };
        McpScannerTab tab = fixture.connected(inventory(List.of(destructiveTool("destroy"))));

        tickFirstToolAndScan(tab);

        assertThat(askedInvoker).hasValue(ScanModeText.of(mode).invoker());
    }

    @Test
    void onScanPersistsDontAskAgainWhenCheckboxTicked() throws Exception {
        fixture.scanPrompt = (parent, tools, count, invoker) -> new DestructiveScanConfirmation.Result(true, true);
        McpScannerTab tab = fixture.connected(inventory(List.of(destructiveTool("destroy"))));

        tickFirstToolAndScan(tab);

        awaitLaunches(1);
        verify(fixture.store).setBoolean(endsWith(".dontAskAgain"), eq(true));
    }

    @Test
    void onScanCancelsWhenUserDismissesModal() throws Exception {
        AtomicBoolean promptInvoked = new AtomicBoolean(false);
        fixture.scanPrompt = (parent, tools, count, invoker) -> {
            promptInvoked.set(true);
            return new DestructiveScanConfirmation.Result(false, false);
        };
        McpScannerTab tab = fixture.connected(inventory(List.of(destructiveTool("destroy"))));

        tickFirstToolAndScan(tab);

        assertThat(promptInvoked).isTrue();
        verify(fixture.scanLauncher, never()).launchScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), anyMap());
    }

    @Test
    void rapidScanClicksStillLaunchAllScans() throws Exception {
        McpScannerTab tab = fixture.connected(inventory(List.of(readOnlyTool("echo"))));

        onEdt(() -> click(scanButton(tab)));
        awaitLaunches(1);
        awaitScanSettled(tab);
        onEdt(() -> click(scanButton(tab)));

        awaitLaunches(2);
    }

    @Test
    void scanButtonShowsStartingWhileTheLaunchRuns() throws Exception {
        McpScannerTab tab = fixture.connected(inventory(List.of(readOnlyTool("echo"))));

        onEdt(() -> {
            click(scanButton(tab));

            assertThat(scanButton(tab).getText()).isEqualTo("Starting scan…");
            assertThat(scanButton(tab).isEnabled()).isFalse();
        });
    }

    @Test
    void eventLogReceivesScanStartedMessageOnClick() throws Exception {
        fixture.eventLog = spy(new McpEventLog(null));
        McpScannerTab tab = fixture.connected(inventory(List.of(readOnlyTool("echo"))));

        onEdt(() -> click(scanButton(tab)));

        awaitLaunches(1);
        ArgumentCaptor<String> messageCaptor = ArgumentCaptor.forClass(String.class);
        verify(fixture.eventLog, atLeastOnce()).kept(messageCaptor.capture());
        assertThat(messageCaptor.getAllValues()).anySatisfy(message -> assertThat(message).contains("Scan started"));
    }

    @Test
    void retiredOauthThirdRefreshFailureCannotCancelReconnectedServersAudit() throws Exception {
        var entered = new AtomicBoolean();
        var release = new CompletableFuture<Void>();
        var refreshes = new AtomicInteger();
        var authA = mock(OAuthAuthCodeStrategy.class);
        var authB = mock(OAuthAuthCodeStrategy.class);
        when(authA.refresh()).thenAnswer(invocation -> {
            if (refreshes.incrementAndGet() == 3) {
                entered.set(true);
                release.join();
            }
            return false;
        });
        when(authA.headers()).thenReturn(Map.of("Authorization", "Bearer A"));
        when(authB.headers()).thenReturn(Map.of("Authorization", "Bearer B"));
        when(authB.refresh()).thenReturn(true);
        when(fixture.clientManager.connect(any())).thenReturn(inventory(List.of(readOnlyTool("echo"))));
        fixture.configStore.addEndpointChangeListener(fixture.identities::clearCredentials);
        McpScannerTab tab = fromEdt(() -> {
            var oauthPanel = ServerConfigPanels.spiedOAuthPanel(fixture.configStore);
            doReturn(authA, authB).when(oauthPanel).completeOAuthDance(any(), any(), any(), any());
            oauthPanel.getOauthIssuerField().setText("https://issuer.example");
            var created = fixture.newTab(ServerConfigPanels.around(oauthPanel));
            endpointField(created).setText("https://server-a.example/mcp");
            fixture.useAuth(AuthTypeNames.OAUTH);
            click(connectButton(created));
            return created;
        });
        awaitConnectLabel(tab, "Disconnect");
        assertThat(authA.refresh()).isFalse();
        assertThat(authA.refresh()).isFalse();
        var executor = Executors.newSingleThreadExecutor();
        try {
            var failedRefresh = executor.submit(authA::refresh);
            awaitSignal().untilTrue(entered);
            onEdt(() -> click(connectButton(tab)));
            McpScannerTabFixture.awaitDisconnected(tab);
            onEdt(() -> {
                endpointField(tab).setText("https://server-b.example/mcp");
                click(connectButton(tab));
            });
            awaitConnectLabel(tab, "Disconnect");
            onEdt(() -> click(scanButton(tab)));
            await().atMost(ofSeconds(5)).untilAsserted(() -> verify(fixture.scanLauncher).launchScan(
                    any(ScanMode.class), anyString(), any(GeneratedScan.class), argThat(headers -> "Bearer B".equals(headers.get("Authorization")))));
            release.complete(null);
            awaitSignal().until(failedRefresh::isDone);
            assertThat(failedRefresh.get()).isFalse();
            onEdt(() -> assertThat(connectButton(tab).getText()).isEqualTo("Disconnect"));
            verify(fixture.scanLauncher, never()).cancelRunningScans();
        } finally {
            release.complete(null);
            executor.shutdownNow();
        }
    }

    @Test
    void connectWithEmptyIssuerTriggersAutoDiscovery() throws Exception {
        DiscoveredMetadata metadata = new DiscoveredMetadata(
                URI.create("https://issuer.example"), DiscoverySource.AS_WELL_KNOWN, null);
        when(fixture.clientManager.connect(any())).thenReturn(emptyInventory());
        AtomicReference<OAuthClientHints> hintsPassedToDance = new AtomicReference<>();
        OAuthAuthCodeStrategy fakeStrategy = mock(OAuthAuthCodeStrategy.class);
        AtomicBoolean danceDone = new AtomicBoolean();

        OAuthConfigPanel spyPanel = fromEdt(() -> {
            OAuthConfigPanel panel = ServerConfigPanels.spiedOAuthPanel(fixture.configStore);
            doReturn(metadata).when(panel).discoverOauthMetadataSync(anyString());
            doAnswer(inv -> {
                hintsPassedToDance.set(inv.getArgument(0));
                danceDone.set(true);
                return fakeStrategy;
            }).when(panel).completeOAuthDance(any(), any(), any(), any());
            panel.getOauthIssuerField().setText("");
            connectWithOAuth(panel);
            return panel;
        });

        awaitSignal().untilTrue(danceDone);
        verify(spyPanel).discoverOauthMetadataSync(ENDPOINT);
        verify(spyPanel).applyDiscoveredMetadata(metadata);
        assertThat(hintsPassedToDance.get()).isNotNull();
        assertThat(hintsPassedToDance.get().issuer()).isEqualTo(URI.create("https://issuer.example"));
        await().atMost(ofSeconds(5)).untilAsserted(() -> onEdt(() ->
                assertThat(spyPanel.getOauthIssuerField().getText()).isEqualTo("https://issuer.example")));
    }

    @Test
    void anOAuthConnectionShowsItsSignInUnderAuthDiscovery() throws Exception {
        when(fixture.clientManager.connect(any())).thenReturn(emptyInventory());
        OAuthAuthCodeStrategy fakeStrategy = mock(OAuthAuthCodeStrategy.class);
        when(fakeStrategy.signInEvidence()).thenReturn(Optional.of(
                new SignInEvidence("{\"issuer\":\"https://manual.issuer.example\"}", Optional.empty())));

        McpScannerTab tab = fromEdt(() -> {
            OAuthConfigPanel panel = ServerConfigPanels.spiedOAuthPanel(fixture.configStore);
            doReturn(fakeStrategy).when(panel).completeOAuthDance(any(), any(), any(), any());
            panel.getOauthIssuerField().setText("https://manual.issuer.example");
            return connectWithOAuth(panel);
        });

        awaitConnectLabel(tab, "Disconnect");
        await().atMost(ofSeconds(5)).untilAsserted(() -> onEdt(() -> assertThat(serverInfo(tab).tabs().titles())
                .containsExactly("Overview", "Server card", "Auth discovery")));
    }

    private static ServerInfoPanel serverInfo(McpScannerTab tab) {
        return SwingTree.descendants(tab).stream().filter(ServerInfoPanel.class::isInstance)
                .map(ServerInfoPanel.class::cast).findFirst().orElseThrow();
    }

    @Test
    void connectWithManualIssuerSkipsAutoDiscovery() throws Exception {
        when(fixture.clientManager.connect(any())).thenReturn(emptyInventory());
        OAuthAuthCodeStrategy fakeStrategy = mock(OAuthAuthCodeStrategy.class);
        AtomicBoolean danceDone = new AtomicBoolean();

        OAuthConfigPanel spyPanel = fromEdt(() -> {
            OAuthConfigPanel panel = ServerConfigPanels.spiedOAuthPanel(fixture.configStore);
            doAnswer(inv -> {
                danceDone.set(true);
                return fakeStrategy;
            }).when(panel).completeOAuthDance(any(), any(), any(), any());
            panel.getOauthIssuerField().setText("https://manual.issuer.example");
            connectWithOAuth(panel);
            return panel;
        });

        awaitSignal().untilTrue(danceDone);
        verify(spyPanel, never()).discoverOauthMetadataSync(anyString());
        verify(spyPanel, never()).applyDiscoveredMetadata(any());
    }

    @Test
    void autoDiscoveryFailureTransitionsToFailedState() throws Exception {
        McpScannerTab tab = fromEdt(() -> {
            OAuthConfigPanel panel = ServerConfigPanels.spiedOAuthPanel(fixture.configStore);
            doThrow(new DiscoveryFailedException("no metadata at any standard path"))
                    .when(panel).discoverOauthMetadataSync(anyString());
            panel.getOauthIssuerField().setText("");
            return connectWithOAuth(panel);
        });

        awaitStatus(tab, ConnectPhase.DISCOVER.displayName() + " failed:");

        onEdt(() -> {
            assertThat(statusText(tab)).contains("no metadata at any standard path");
            assertThat(connectButton(tab).getText()).isEqualTo("Connect");
        });
    }

    @Test
    void autoAuthWithIncompletePreRegisteredSettingsStillConnectsToAServerThatNeedsNoAuth() throws Exception {
        AtomicBoolean connected = new AtomicBoolean();
        AtomicReference<AuthStrategy> authUsed = new AtomicReference<>();
        when(fixture.clientManager.connect(any())).thenAnswer(inv -> {
            authUsed.set(((McpServerConfig) inv.getArgument(0)).auth());
            connected.set(true);
            return emptyInventory();
        });

        onEdt(() -> {
            OAuthConfigPanel oauthPanel = ServerConfigPanels.spiedOAuthPanel(fixture.configStore);
            doReturn(new AuthRequirement.NotRequired()).when(oauthPanel).probeAuthRequirement(anyString(), any());
            oauthPanel.getRegistrationModeSelector().setSelectedItem(RegistrationMode.PRE_REGISTERED);
            McpScannerTab tab = fixture.newTab(ServerConfigPanels.around(oauthPanel));
            endpointField(tab).setText(ENDPOINT);
            fixture.useAuth(AuthTypeNames.AUTO);
            click(connectButton(tab));
        });

        awaitSignal().untilTrue(connected);
        assertThat(authUsed.get()).isInstanceOf(NoAuthStrategy.class);
    }

    @Test
    void onConnect_rejectsNonHttpScheme() throws Exception {
        onEdt(() -> {
            McpScannerTab tab = fixture.newTab();
            endpointField(tab).setText("ftp://x");

            click(connectButton(tab));

            assertThat(statusText(tab)).isEqualTo(ConnectPhase.CONNECT.displayName()
                    + " failed: Endpoint must use http or https");
        });
        verify(fixture.clientManager, never()).connect(any());
    }

    @Test
    void connectIsDisabledWithAReasonUntilThePrimaryUsersGrantIsComplete() throws Exception {
        var panel = fromEdt(this::panelWithEnterpriseProvider);
        var tab = fromEdt(() -> fixture.newTab(panel));
        onEdt(() -> {
            endpointField(tab).setText(ENDPOINT);
            selectAuth(panel, "CLIENT_CREDENTIALS");
        });
        onEdt(() -> {
            assertThat(connectButton(tab).isEnabled()).isFalse();
            assertThat(connectButton(tab).getToolTipText()).contains("client ID");

            fillGrant(panel, OptionalGrantSettings.Profile.CLIENT_CREDENTIALS, "machine-client", "secret");

            assertThat(connectButton(tab).isEnabled()).isTrue();
            assertThat(connectButton(tab).getToolTipText()).contains("Connect");
        });
    }

    @Test
    void connectIsDisabledUntilTheEndpointIsEntered() throws Exception {
        onEdt(() -> {
            var tab = fixture.newTab(panelWithEnterpriseProvider());
            fixture.useAuth(AuthTypeNames.NONE);
            endpointField(tab).setText("");

            assertThat(connectButton(tab).isEnabled()).isFalse();
            endpointField(tab).setText(ENDPOINT);
            assertThat(connectButton(tab).isEnabled()).isTrue();
        });
    }

    private McpScannerTab connectWithOAuth(OAuthConfigPanel oauthPanel) {
        McpScannerTab tab = fixture.newTab(ServerConfigPanels.around(oauthPanel));
        endpointField(tab).setText(ENDPOINT);
        fixture.useAuth(AuthTypeNames.OAUTH);
        click(connectButton(tab));
        return tab;
    }

    private void tickFirstToolAndScan(McpScannerTab tab) throws Exception {
        onEdt(() -> {
            tools(tab).getTableModel().setValueAt(true, 0, 0);
            click(scanButton(tab));
        });
    }

    private static ConditionFactory awaitSignal() {
        return Polling.within(ofSeconds(5));
    }

    private void awaitLaunches(int count) {
        await().atMost(ofSeconds(5)).untilAsserted(() -> verify(fixture.scanLauncher, times(count))
                .launchScan(any(ScanMode.class), anyString(), any(GeneratedScan.class), anyMap()));
    }

    private static void awaitScanSettled(McpScannerTab tab) {
        await().atMost(ofSeconds(5)).until(() -> fromEdt(() -> !scanButton(tab).getText()
                .equals(ScanLaunchPresenter.STARTING)));
    }
}
