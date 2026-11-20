package com.mcpscanner.ui.connect;

import com.mcpscanner.config.AuthTypeNames;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.discovery.AuthRequirement;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.auth.oauth.discovery.DiscoverySource;
import com.mcpscanner.client.ConnectResult;
import com.mcpscanner.client.McpClientManager;
import com.mcpscanner.client.McpServerConfig;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.mcp.ServerMetadata;
import com.mcpscanner.ui.OAuthConnectSupport;
import com.mcpscanner.ui.state.ConnectAttempt;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.mcpscanner.core.oauth.RegistrationMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import com.mcpscanner.identity.credentials.CredentialNeed;
import com.mcpscanner.identity.credentials.CredentialNeedException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AutoAuthConnectTest {

    private static final String ENDPOINT = "https://mcp.example.com/mcp";
    private static final URI ISSUER = URI.create("https://issuer.example");

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
        when(clientManager.connect(any())).thenReturn(new ConnectResult(
                List.of(), List.of(), List.of(), List.of(), ServerMetadata.empty()));
    }

    @Test
    void serverWithoutAuthConnectsWithNoAuthAndSaysSo() {
        when(support.probeAuthRequirement(ENDPOINT, TransportType.AUTO)).thenReturn(new AuthRequirement.NotRequired());

        ConnectionAttemptResult outcome = connect();

        ArgumentCaptor<McpServerConfig> config = ArgumentCaptor.forClass(McpServerConfig.class);
        verify(clientManager).connect(config.capture());
        assertThat(config.getValue().auth()).isInstanceOf(NoAuthStrategy.class);
        assertThat(outcome.autoResolution()).contains("Detect → None");
        verify(support, never()).completeOAuthDance(any(), any(), any(), any());
        assertThat(eventLog.snapshot()).anyMatch(entry -> entry.message().contains("Auth: Detect → None"));
    }

    @Test
    void everyConnectBeginsANewSignInAttemptBeforeProbingTheServer() {
        when(support.probeAuthRequirement(ENDPOINT, TransportType.AUTO)).thenReturn(new AuthRequirement.NotRequired());

        connect();
        connect();

        InOrder order = inOrder(support);
        order.verify(support).beginSignInAttempt();
        order.verify(support).probeAuthRequirement(ENDPOINT, TransportType.AUTO);
        order.verify(support).beginSignInAttempt();
        order.verify(support).probeAuthRequirement(ENDPOINT, TransportType.AUTO);
    }

    @Test
    void oauthServerRunsTheBrowserFlowWithDiscoveredIssuerAndScopes() {
        AuthorizationServerMetadata asMetadata = mock(AuthorizationServerMetadata.class);
        DiscoveredMetadata discovered = new DiscoveredMetadata(
                ISSUER, DiscoverySource.WWW_AUTHENTICATE_HEADER, asMetadata, List.of("tools:read"));
        when(support.probeAuthRequirement(ENDPOINT, TransportType.AUTO)).thenReturn(new AuthRequirement.OAuth(discovered));
        OAuthAuthCodeStrategy strategy = mock(OAuthAuthCodeStrategy.class);
        when(strategy.registrationMode()).thenReturn(Optional.of(RegistrationMode.DCR));
        when(support.completeOAuthDance(any(), any(), any(), any())).thenReturn(strategy);

        ConnectionAttemptResult outcome = connect();

        ArgumentCaptor<OAuthClientHints> hints = ArgumentCaptor.forClass(OAuthClientHints.class);
        verify(support).applyDiscoveredMetadata(discovered);
        verify(support).completeOAuthDance(hints.capture(), any(), any(), org.mockito.ArgumentMatchers.same(asMetadata));
        assertThat(hints.getValue().issuer()).isEqualTo(ISSUER);
        assertThat(hints.getValue().scopes()).containsExactly("tools:read");
        assertThat(outcome.oauthStrategy()).isSameAs(strategy);
        assertThat(outcome.autoResolution()).contains("Detect → OAuth 2.1 (Authorization code, DCR)");
        assertThat(eventLog.snapshot()).anyMatch(entry ->
                entry.message().contains("Auth: Detect → OAuth 2.1 (Authorization code, DCR)"));
    }

    @Test
    void oauthServerRequestsOnlyTheTickedScopesWhenTheProbeDiscoversMore() {
        DiscoveredMetadata discovered = new DiscoveredMetadata(ISSUER, DiscoverySource.WWW_AUTHENTICATE_HEADER,
                mock(AuthorizationServerMetadata.class),
                List.of("mcp:tools", "mcp:resources", "mcp:prompts", "mcp:admin"));
        when(support.probeAuthRequirement(ENDPOINT, TransportType.AUTO)).thenReturn(new AuthRequirement.OAuth(discovered));
        when(support.completeOAuthDance(any(), any(), any(), any())).thenReturn(mock(OAuthAuthCodeStrategy.class));
        OAuthClientHints ticked = new OAuthClientHints(null, List.of("mcp:tools"), null, null, true,
                OAuthClientHints.DEFAULT_REDIRECT_PORT, Duration.ofSeconds(120), RegistrationMode.AUTO, null,
                new com.mcpscanner.auth.oauth.ScopeSelection(
                        java.util.Set.of("mcp:resources", "mcp:prompts", "mcp:admin"), List.of()));

        coordinator.connect(autoAttempt(ticked), (phase, message) -> {}, () -> {});

        ArgumentCaptor<OAuthClientHints> hints = ArgumentCaptor.forClass(OAuthClientHints.class);
        verify(support).completeOAuthDance(hints.capture(), any(), any(), any());
        assertThat(hints.getValue().scopes()).containsExactly("mcp:tools");
    }

    @Test
    void staleIssuerFromAnEarlierDiscoveryDoesNotOverrideTheProbe() {
        DiscoveredMetadata discovered = new DiscoveredMetadata(
                ISSUER, DiscoverySource.PRM_WELL_KNOWN, mock(AuthorizationServerMetadata.class));
        when(support.probeAuthRequirement(ENDPOINT, TransportType.AUTO)).thenReturn(new AuthRequirement.OAuth(discovered));
        when(support.completeOAuthDance(any(), any(), any(), any())).thenReturn(mock(OAuthAuthCodeStrategy.class));

        coordinator.connect(autoAttempt(hintsWithIssuer(URI.create("https://stale.example"))),
                (phase, message) -> {}, () -> {});

        ArgumentCaptor<OAuthClientHints> hints = ArgumentCaptor.forClass(OAuthClientHints.class);
        verify(support).completeOAuthDance(hints.capture(), any(), any(), any());
        assertThat(hints.getValue().issuer()).isEqualTo(ISSUER);
    }

    @Test
    void registrationSettingsFromTheOAuthPanelAreKept() {
        DiscoveredMetadata discovered = new DiscoveredMetadata(
                ISSUER, DiscoverySource.PRM_WELL_KNOWN, mock(AuthorizationServerMetadata.class));
        when(support.probeAuthRequirement(ENDPOINT, TransportType.AUTO)).thenReturn(new AuthRequirement.OAuth(discovered));
        when(support.completeOAuthDance(any(), any(), any(), any())).thenReturn(mock(OAuthAuthCodeStrategy.class));
        OAuthClientHints configured = new OAuthClientHints(null, List.of(), "client", "secret", false, 8765,
                Duration.ofSeconds(30), RegistrationMode.PRE_REGISTERED, null);

        coordinator.connect(autoAttempt(configured), (phase, message) -> {}, () -> {});

        ArgumentCaptor<OAuthClientHints> hints = ArgumentCaptor.forClass(OAuthClientHints.class);
        verify(support).completeOAuthDance(hints.capture(), any(), any(), any());
        assertThat(hints.getValue().registrationMode()).isEqualTo(RegistrationMode.PRE_REGISTERED);
        assertThat(hints.getValue().clientId()).isEqualTo("client");
    }

    @Test
    void unsupportedChallengeStopsWithTheActionableReasonAndNeverConnects() {
        String reason = "Server did not answer the unauthenticated probe";
        when(support.probeAuthRequirement(ENDPOINT, TransportType.AUTO)).thenReturn(new AuthRequirement.Unsupported(reason));

        assertThatThrownBy(this::connect).isInstanceOf(IllegalStateException.class).hasMessage(reason);

        verify(clientManager, never()).connect(any());
    }

    @Test
    void aServerNeedingCredentialsWithoutOAuthAsksForThemAndNeverConnects() {
        String answer = "The server needs credentials and advertises no OAuth sign-in";
        when(support.probeAuthRequirement(ENDPOINT, TransportType.AUTO))
                .thenReturn(new AuthRequirement.CredentialsRequired(answer, true));

        assertThatThrownBy(this::connect).isInstanceOfSatisfying(CredentialNeedException.class,
                needed -> assertThat(needed.need()).isEqualTo(new CredentialNeed.ServerRefused(answer, true)));

        verify(clientManager, never()).connect(any());
        verify(support, never()).completeOAuthDance(any(), any(), any(), any());
    }

    @Test
    void incompleteOAuthSettingsDoNotBlockAServerThatNeedsNoAuth() {
        when(support.probeAuthRequirement(ENDPOINT, TransportType.AUTO)).thenReturn(new AuthRequirement.NotRequired());

        ConnectionAttemptResult outcome = coordinator.connect(invalidOAuthSettingsAttempt(),
                (phase, message) -> {}, () -> {});

        assertThat(outcome.autoResolution()).isEqualTo("Detect → None");
        verify(support, never()).completeOAuthDance(any(), any(), any(), any());
    }

    @Test
    void incompleteOAuthSettingsFailClearlyOnceTheServerAsksForOAuth() {
        DiscoveredMetadata discovered = new DiscoveredMetadata(
                ISSUER, DiscoverySource.PRM_WELL_KNOWN, mock(AuthorizationServerMetadata.class));
        when(support.probeAuthRequirement(ENDPOINT, TransportType.AUTO)).thenReturn(new AuthRequirement.OAuth(discovered));

        assertThatThrownBy(() -> coordinator.connect(invalidOAuthSettingsAttempt(), (phase, message) -> {}, () -> {}))
                .isInstanceOfSatisfying(CredentialNeedException.class, needed -> assertThat(needed.need())
                        .isEqualTo(new CredentialNeed.OAuthSignInIncomplete("Client ID is required")))
                .hasMessageContaining("The server uses OAuth")
                .hasMessageContaining("Client ID is required");

        verify(support, never()).completeOAuthDance(any(), any(), any(), any());
        verify(clientManager, never()).connect(any());
    }

    private static ConnectAttempt invalidOAuthSettingsAttempt() {
        return ConnectAttempt.withAuto(ENDPOINT, TransportType.AUTO, "mcp.example.com",
                AuthTypeNames.AUTO, null, URI.create(ENDPOINT), "Client ID is required");
    }

    private ConnectionAttemptResult connect() {
        return coordinator.connect(autoAttempt(hintsWithIssuer(null)), (phase, message) -> {}, () -> {});
    }

    private static ConnectAttempt autoAttempt(OAuthClientHints hints) {
        return ConnectAttempt.withOauth(ENDPOINT, TransportType.AUTO, "mcp.example.com",
                AuthTypeNames.AUTO, hints, URI.create(ENDPOINT));
    }

    private static OAuthClientHints hintsWithIssuer(URI issuer) {
        return new OAuthClientHints(issuer, List.of(), null, null, true,
                OAuthClientHints.DEFAULT_REDIRECT_PORT, Duration.ofSeconds(120));
    }
}
