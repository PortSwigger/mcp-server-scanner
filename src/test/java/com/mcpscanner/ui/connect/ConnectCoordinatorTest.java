package com.mcpscanner.ui.connect;

import com.mcpscanner.config.AuthTypeNames;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.auth.oauth.discovery.DiscoverySource;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.McpPromptDefinition;
import com.mcpscanner.mcp.McpResourceDefinition;
import com.mcpscanner.mcp.McpResourceTemplateDefinition;
import com.mcpscanner.mcp.McpToolDefinition;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.ui.OAuthConnectSupport;
import com.mcpscanner.ui.state.ConnectAttempt;
import com.mcpscanner.ui.state.ConnectPhase;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.Scope;
import com.mcpscanner.core.oauth.RegistrationMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.util.Optional;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ConnectCoordinatorTest {

    private static final String ENDPOINT = "https://mcp.example.com/mcp";
    private static final String HOST = "mcp.example.com";

    private OAuthConnectSupport support;
    private McpClientManager clientManager;
    private McpEventLog eventLog;
    private ConnectCoordinator coordinator;

    @BeforeEach
    void setUp() {
        support = mock(OAuthConnectSupport.class);
        clientManager = mock(McpClientManager.class);
        eventLog = new McpEventLog(null);
        coordinator = new ConnectCoordinator(support, clientManager, eventLog);
    }

    @Test
    void explicitlySelectedMachineAndEnterpriseGrantsReachTheBackend() {
        for (var profile : com.mcpscanner.auth.grants.OptionalGrantSettings.Profile.values()) {
            var settings = new com.mcpscanner.auth.grants.OptionalGrantSettings(profile, URI.create("https://issuer.example"), "client", "secret",
                    java.util.Set.of("read"), com.mcpscanner.core.oauth.ClientCredentialsAuthentication.basic(), "company");
            AuthStrategy credentials = () -> java.util.Map.of("Authorization", "Bearer grant-token");
            var configured = new ConnectCoordinator(support, clientManager, eventLog, (endpoint, snapshot) -> {
                assertThat(endpoint).isEqualTo(URI.create(ENDPOINT));
                assertThat(snapshot).isSameAs(settings);
                return credentials;
            });
            configured.connect(ConnectAttempt.withOptionalGrant(ENDPOINT, TransportType.SSE, HOST, AuthTypeNames.OAUTH, settings),
                    (phase, message) -> {}, () -> {});
            verify(clientManager, org.mockito.Mockito.atLeastOnce()).connect(
                    org.mockito.ArgumentMatchers.argThat(config -> config.auth() == credentials));
        }
        verify(support, never()).completeOAuthDance(any(), any(), any(), any());
    }

    @Test
    void rejectedOptionalGrantDoesNotConnectAnonymously() {
        var settings = new com.mcpscanner.auth.grants.OptionalGrantSettings(
                com.mcpscanner.auth.grants.OptionalGrantSettings.Profile.CLIENT_CREDENTIALS, URI.create("https://issuer.example"), "client", "secret",
                java.util.Set.of(), com.mcpscanner.core.oauth.ClientCredentialsAuthentication.basic(), null);
        var configured = new ConnectCoordinator(support, clientManager, eventLog, (endpoint, snapshot) -> {
            throw new IllegalArgumentException("Server does not advertise this grant");
        });
        assertThatThrownBy(() -> configured.connect(ConnectAttempt.withOptionalGrant(ENDPOINT,
                TransportType.SSE, HOST, AuthTypeNames.OAUTH, settings),
                (phase, message) -> {}, () -> {})).hasMessageContaining("does not advertise");
        verify(clientManager, never()).connect(any());
    }

    @Test
    void machineAuthenticationWithoutConfiguredBackendFailsBeforeConnecting() {
        var settings = new com.mcpscanner.auth.grants.OptionalGrantSettings(
                com.mcpscanner.auth.grants.OptionalGrantSettings.Profile.CLIENT_CREDENTIALS, URI.create("https://issuer.example"), "client", "secret",
                java.util.Set.of(), com.mcpscanner.core.oauth.ClientCredentialsAuthentication.basic(), null);
        var attempt = ConnectAttempt.withOptionalGrant(ENDPOINT, TransportType.STREAMABLE_HTTP,
                HOST, AuthTypeNames.OAUTH, settings);
        assertThatThrownBy(() -> coordinator.connect(attempt, (phase, message) -> {}, () -> {}))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("configured");
        verify(clientManager, never()).connect(any());
    }

    @Test
    void noOauthPathBuildsConfigAndConnectsWithoutStrategy() throws Exception {
        AuthStrategy snapshot = java.util.Map::of;
        ConnectResult result = emptyResult();
        when(clientManager.connect(any())).thenReturn(result);

        ConnectAttempt attempt = ConnectAttempt.withSnapshot(
                ENDPOINT, TransportType.STREAMABLE_HTTP, HOST, "None", snapshot);

        ConnectionAttemptResult outcome = coordinator.connect(attempt, (phase, message) -> {}, () -> {});

        assertThat(outcome.result()).isSameAs(result);
        assertThat(outcome.oauthStrategy()).isNull();

        ArgumentCaptor<McpServerConfig> cfg = ArgumentCaptor.forClass(McpServerConfig.class);
        verify(clientManager).connect(cfg.capture());
        assertThat(cfg.getValue().endpoint()).isEqualTo(ENDPOINT);
        assertThat(cfg.getValue().transport()).isEqualTo(TransportType.STREAMABLE_HTTP);
        assertThat(cfg.getValue().auth()).isSameAs(snapshot);

        verify(support, never()).discoverOauthMetadataSync(anyString());
        verify(support, never()).completeOAuthDance(any(), any(), any(), any());
    }

    @Test
    void oauthWithASignedInSessionConnectsWithoutAnotherDance() throws Exception {
        OAuthAuthCodeStrategy session = mock(OAuthAuthCodeStrategy.class);
        when(clientManager.connect(any())).thenReturn(emptyResult());

        ConnectionAttemptResult outcome = coordinator.connect(ConnectAttempt.withSnapshot(ENDPOINT,
                TransportType.STREAMABLE_HTTP, HOST, AuthTypeNames.OAUTH, session), (phase, message) -> {},
                () -> {});

        assertThat(outcome.resolvedAuth()).isSameAs(session);
        assertThat(outcome.oauthStrategy()).isNull();
        verify(support, never()).completeOAuthDance(any(), any(), any(), any());
    }

    @Test
    void explicitOAuthBeginsANewSignInAttemptBeforeTheDance() {
        when(support.completeOAuthDance(any(), any(), any(), any())).thenReturn(mock(OAuthAuthCodeStrategy.class));
        when(clientManager.connect(any())).thenReturn(emptyResult());

        coordinator.connect(ConnectAttempt.withOauth(ENDPOINT, TransportType.STREAMABLE_HTTP, HOST,
                AuthTypeNames.OAUTH, oauthHints(URI.create("https://manual.issuer.example")), URI.create(ENDPOINT)),
                (phase, message) -> {}, () -> {});

        org.mockito.InOrder order = org.mockito.Mockito.inOrder(clientManager, support);
        order.verify(clientManager).beginConnectAttempt();
        order.verify(support).beginSignInAttempt();
        order.verify(support).completeOAuthDance(any(), any(), any(), any());
        order.verify(clientManager).connect(any());
    }

    @Test
    void oauthReportsThatItIsWaitingForBrowserSignInWithItsTimeout() {
        OAuthClientHints hints = oauthHints(URI.create("https://manual.issuer.example"));
        when(support.completeOAuthDance(any(), any(), any(), any())).thenReturn(mock(OAuthAuthCodeStrategy.class));
        when(clientManager.connect(any())).thenReturn(emptyResult());
        List<String> messages = new ArrayList<>();

        coordinator.connect(ConnectAttempt.withOauth(ENDPOINT, TransportType.STREAMABLE_HTTP, HOST,
                AuthTypeNames.OAUTH, hints, URI.create(ENDPOINT)), (phase, message) -> messages.add(message),
                () -> {});

        assertThat(messages).contains("Waiting for browser sign-in (times out in "
                + hints.timeout().toMinutes() + " min)…");
    }

    @Test
    void oauthWithPresetIssuerSkipsDiscoveryAndCarriesStrategy() throws Exception {
        OAuthClientHints hints = oauthHints(URI.create("https://manual.issuer.example"));
        OAuthAuthCodeStrategy strategy = mock(OAuthAuthCodeStrategy.class);
        ConnectResult result = emptyResult();
        when(support.completeOAuthDance(any(), any(), any(), any())).thenReturn(strategy);
        when(clientManager.connect(any())).thenReturn(result);

        ConnectAttempt attempt = ConnectAttempt.withOauth(
                ENDPOINT, TransportType.STREAMABLE_HTTP, HOST, AuthTypeNames.OAUTH, hints, URI.create(ENDPOINT));

        ConnectionAttemptResult outcome = coordinator.connect(attempt, (phase, message) -> {}, () -> {});

        assertThat(outcome.oauthStrategy()).isSameAs(strategy);
        assertThat(outcome.result()).isSameAs(result);
        verify(support, never()).discoverOauthMetadataSync(anyString());
        verify(support, never()).applyDiscoveredMetadata(any());
        verify(support).completeOAuthDance(any(), any(), any(), isNull());

        ArgumentCaptor<McpServerConfig> cfg = ArgumentCaptor.forClass(McpServerConfig.class);
        verify(clientManager).connect(cfg.capture());
        assertThat(cfg.getValue().auth()).isSameAs(strategy);
    }

    @Test
    void presetIssuerAdvertisesTheRegistrationEndpointTheDanceResolved() throws Exception {
        URI registration = URI.create("https://manual.issuer.example/register");
        when(support.completeOAuthDance(any(), any(), any(), any())).thenReturn(mock(OAuthAuthCodeStrategy.class));
        when(support.authorizationServerOfLastDance()).thenReturn(() -> Optional.of(registration));
        when(clientManager.connect(any())).thenReturn(emptyResult());
        ConnectAttempt attempt = ConnectAttempt.withOauth(ENDPOINT, TransportType.STREAMABLE_HTTP, HOST,
                AuthTypeNames.OAUTH, oauthHints(URI.create("https://manual.issuer.example")),
                URI.create(ENDPOINT));

        ConnectionAttemptResult outcome = coordinator.connect(attempt, (phase, message) -> {}, () -> {});

        assertThat(outcome.authorizationServer().registrationEndpoint()).contains(registration);
    }

    @Test
    void oauthWithNullIssuerDiscoversAppliesMergesThenDances() throws Exception {
        OAuthClientHints hints = oauthHints(null);
        AuthorizationServerMetadata asMetadata = mock(AuthorizationServerMetadata.class);
        DiscoveredMetadata metadata = new DiscoveredMetadata(
                URI.create("https://issuer.example"), DiscoverySource.AS_WELL_KNOWN, asMetadata);
        OAuthAuthCodeStrategy strategy = mock(OAuthAuthCodeStrategy.class);
        when(support.discoverOauthMetadataSync(anyString())).thenReturn(metadata);
        when(support.completeOAuthDance(any(), any(), any(), any())).thenReturn(strategy);
        when(clientManager.connect(any())).thenReturn(emptyResult());

        ConnectAttempt attempt = ConnectAttempt.withOauth(
                ENDPOINT, TransportType.STREAMABLE_HTTP, HOST, AuthTypeNames.OAUTH, hints, URI.create(ENDPOINT));

        ArgumentCaptor<OAuthClientHints> dancedHints = ArgumentCaptor.forClass(OAuthClientHints.class);
        ArgumentCaptor<AuthorizationServerMetadata> dancedMetadata =
                ArgumentCaptor.forClass(AuthorizationServerMetadata.class);

        ConnectionAttemptResult outcome = coordinator.connect(attempt, (phase, message) -> {}, () -> {});

        verify(support).discoverOauthMetadataSync(ENDPOINT);
        verify(support).applyDiscoveredMetadata(metadata);
        verify(support).completeOAuthDance(dancedHints.capture(), any(), any(), dancedMetadata.capture());
        assertThat(dancedHints.getValue().issuer()).isEqualTo(URI.create("https://issuer.example"));
        assertThat(dancedMetadata.getValue()).isSameAs(asMetadata);
        assertThat(outcome.oauthStrategy()).isSameAs(strategy);
    }

    @ParameterizedTest
    @MethodSource("registrationHints")
    void oauthDiscoveryPreservesRegistrationSettings(OAuthClientHints hints) {
        URI issuer = URI.create("https://issuer.example");
        AuthorizationServerMetadata asMetadata = mock(AuthorizationServerMetadata.class);
        when(asMetadata.getScopes()).thenReturn(new Scope("admin"));
        DiscoveredMetadata metadata = new DiscoveredMetadata(issuer, DiscoverySource.WWW_AUTHENTICATE_HEADER, asMetadata,
                List.of("tools:read", "resources:read"));
        when(support.discoverOauthMetadataSync(ENDPOINT)).thenReturn(metadata);
        when(support.completeOAuthDance(any(), any(), any(), any())).thenReturn(mock(OAuthAuthCodeStrategy.class));
        when(clientManager.connect(any())).thenReturn(emptyResult());
        ConnectAttempt attempt = ConnectAttempt.withOauth(
                ENDPOINT, TransportType.STREAMABLE_HTTP, HOST, AuthTypeNames.OAUTH, hints, URI.create(ENDPOINT));

        coordinator.connect(attempt, (phase, message) -> {}, () -> {});

        ArgumentCaptor<OAuthClientHints> dancedHints = ArgumentCaptor.forClass(OAuthClientHints.class);
        verify(support).completeOAuthDance(dancedHints.capture(), any(), any(), any());
        assertThat(dancedHints.getValue()).isEqualTo(new OAuthClientHints(
                issuer, List.of("tools:read", "resources:read"), hints.clientId(), hints.clientSecret(),
                hints.allowDcr(), hints.redirectPort(), hints.timeout(), hints.registrationMode(), hints.clientMetadataUrl()));
    }

    private static Stream<OAuthClientHints> registrationHints() {
        URI metadataUrl = URI.create("https://client.example/oauth/client.json");
        return Stream.of(
                new OAuthClientHints(null, List.of("original"), null, null, false,
                        8791, Duration.ofSeconds(75), RegistrationMode.CIMD, metadataUrl),
                new OAuthClientHints(null, List.of("original"), "configured-client", "configured-secret", true,
                        8792, Duration.ofSeconds(90), RegistrationMode.AUTO, metadataUrl));
    }

    @Test
    void discoveredRegistrationEndpointIsAdvertisedToScanGeneration() throws Exception {
        URI registration = URI.create("https://issuer.example/register");
        AuthorizationServerMetadata asMetadata = mock(AuthorizationServerMetadata.class);
        when(asMetadata.getRegistrationEndpointURI()).thenReturn(registration);
        when(support.discoverOauthMetadataSync(anyString())).thenReturn(new DiscoveredMetadata(
                URI.create("https://issuer.example"), DiscoverySource.AS_WELL_KNOWN, asMetadata));
        when(support.completeOAuthDance(any(), any(), any(), any())).thenReturn(mock(OAuthAuthCodeStrategy.class));
        when(clientManager.connect(any())).thenReturn(emptyResult());
        ConnectAttempt attempt = ConnectAttempt.withOauth(ENDPOINT, TransportType.STREAMABLE_HTTP, HOST,
                AuthTypeNames.OAUTH, oauthHints(null), URI.create(ENDPOINT));

        ConnectionAttemptResult outcome = coordinator.connect(attempt, (phase, message) -> {}, () -> {});

        assertThat(outcome.authorizationServer().registrationEndpoint()).contains(registration);
    }

    @Test
    void discoveredMetadataWithoutRegistrationEndpointAdvertisesNone() throws Exception {
        when(support.discoverOauthMetadataSync(anyString())).thenReturn(new DiscoveredMetadata(
                URI.create("https://issuer.example"), DiscoverySource.AS_WELL_KNOWN,
                mock(AuthorizationServerMetadata.class)));
        when(support.completeOAuthDance(any(), any(), any(), any())).thenReturn(mock(OAuthAuthCodeStrategy.class));
        when(clientManager.connect(any())).thenReturn(emptyResult());
        ConnectAttempt attempt = ConnectAttempt.withOauth(ENDPOINT, TransportType.STREAMABLE_HTTP, HOST,
                AuthTypeNames.OAUTH, oauthHints(null), URI.create(ENDPOINT));

        assertThat(coordinator.connect(attempt, (phase, message) -> {}, () -> {})
                .authorizationServer().registrationEndpoint()).isEmpty();
    }

    @Test
    void connectionWithoutOauthDiscoveryAdvertisesNoRegistrationEndpoint() throws Exception {
        when(clientManager.connect(any())).thenReturn(emptyResult());
        ConnectAttempt attempt = ConnectAttempt.withSnapshot(
                ENDPOINT, TransportType.STREAMABLE_HTTP, HOST, "None", java.util.Map::of);

        assertThat(coordinator.connect(attempt, (phase, message) -> {}, () -> {})
                .authorizationServer().registrationEndpoint()).isEmpty();
    }

    @Test
    void danceFailurePropagates() {
        OAuthClientHints hints = oauthHints(URI.create("https://manual.issuer.example"));
        when(support.completeOAuthDance(any(), any(), any(), any()))
                .thenThrow(new RuntimeException("dance boom"));

        ConnectAttempt attempt = ConnectAttempt.withOauth(
                ENDPOINT, TransportType.STREAMABLE_HTTP, HOST, AuthTypeNames.OAUTH, hints, URI.create(ENDPOINT));

        assertThatThrownBy(() -> coordinator.connect(attempt, (phase, message) -> {}, () -> {}))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("dance boom");
    }

    @Test
    void connectFailurePropagates() throws Exception {
        when(clientManager.connect(any())).thenThrow(new RuntimeException("connect boom"));

        ConnectAttempt attempt = ConnectAttempt.withSnapshot(
                ENDPOINT, TransportType.STREAMABLE_HTTP, HOST, "None", java.util.Map::of);

        assertThatThrownBy(() -> coordinator.connect(attempt, (phase, message) -> {}, () -> {}))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("connect boom");
    }

    @Test
    void progressPhasesReportedInOrderForOauthAutoDiscover() throws Exception {
        OAuthClientHints hints = oauthHints(null);
        when(support.discoverOauthMetadataSync(anyString())).thenReturn(new DiscoveredMetadata(
                URI.create("https://issuer.example"), DiscoverySource.AS_WELL_KNOWN, null));
        when(support.completeOAuthDance(any(), any(), any(), any())).thenReturn(mock(OAuthAuthCodeStrategy.class));
        when(clientManager.connect(any())).thenReturn(emptyResult());

        ConnectAttempt attempt = ConnectAttempt.withOauth(
                ENDPOINT, TransportType.STREAMABLE_HTTP, HOST, AuthTypeNames.OAUTH, hints, URI.create(ENDPOINT));

        List<ConnectPhase> phases = new ArrayList<>();
        coordinator.connect(attempt, (phase, message) -> phases.add(phase), () -> {});

        assertThat(phases).containsExactly(ConnectPhase.DISCOVER, ConnectPhase.OAUTH, ConnectPhase.CONNECT);
    }

    @Test
    void terminalFailureCallbackWiredOntoStrategy() throws Exception {
        OAuthClientHints hints = oauthHints(URI.create("https://manual.issuer.example"));
        OAuthAuthCodeStrategy strategy = mock(OAuthAuthCodeStrategy.class);
        when(support.completeOAuthDance(any(), any(), any(), any())).thenReturn(strategy);
        when(clientManager.connect(any())).thenReturn(emptyResult());

        ConnectAttempt attempt = ConnectAttempt.withOauth(
                ENDPOINT, TransportType.STREAMABLE_HTTP, HOST, AuthTypeNames.OAUTH, hints, URI.create(ENDPOINT));

        Runnable terminalCallback = () -> {};
        coordinator.connect(attempt, (phase, message) -> {}, terminalCallback);

        verify(strategy).setTerminalFailureListener(terminalCallback);
    }

    @Test
    void aReusedSignedInSessionReportsATerminalRefreshFailureToThisConnection() throws Exception {
        OAuthAuthCodeStrategy savedSession = mock(OAuthAuthCodeStrategy.class);
        when(clientManager.connect(any())).thenReturn(emptyResult());
        ConnectAttempt attempt = ConnectAttempt.withSnapshot(
                ENDPOINT, TransportType.STREAMABLE_HTTP, HOST, AuthTypeNames.OAUTH, savedSession);

        Runnable terminalCallback = () -> {};
        coordinator.connect(attempt, (phase, message) -> {}, terminalCallback);

        verify(savedSession).setTerminalFailureListener(terminalCallback);
        verify(support, never()).completeOAuthDance(any(), any(), any(), any());
    }

    private static OAuthClientHints oauthHints(URI issuer) {
        return new OAuthClientHints(issuer, List.of(), null, null, true,
                OAuthClientHints.DEFAULT_REDIRECT_PORT, Duration.ofSeconds(120));
    }

    private static ConnectResult emptyResult() {
        return new ConnectResult(
                List.<McpToolDefinition>of(),
                List.<McpResourceDefinition>of(),
                List.<McpResourceTemplateDefinition>of(),
                List.<McpPromptDefinition>of(),
                ServerMetadata.empty());
    }
}
