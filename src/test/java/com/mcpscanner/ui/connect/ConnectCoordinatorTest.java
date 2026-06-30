package com.mcpscanner.ui.connect;

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
import com.mcpscanner.ui.ServerConfigPanel;
import com.mcpscanner.ui.state.ConnectAttempt;
import com.mcpscanner.ui.state.ConnectPhase;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

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
    void oauthWithPresetIssuerSkipsDiscoveryAndCarriesStrategy() throws Exception {
        OAuthClientHints hints = oauthHints(URI.create("https://manual.issuer.example"));
        OAuthAuthCodeStrategy strategy = mock(OAuthAuthCodeStrategy.class);
        ConnectResult result = emptyResult();
        when(support.completeOAuthDance(any(), any(), any(), any())).thenReturn(strategy);
        when(clientManager.connect(any())).thenReturn(result);

        ConnectAttempt attempt = ConnectAttempt.withOauth(
                ENDPOINT, TransportType.STREAMABLE_HTTP, HOST, ServerConfigPanel.AUTH_OAUTH, hints, URI.create(ENDPOINT));

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
                ENDPOINT, TransportType.STREAMABLE_HTTP, HOST, ServerConfigPanel.AUTH_OAUTH, hints, URI.create(ENDPOINT));

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

    @Test
    void danceFailurePropagates() {
        OAuthClientHints hints = oauthHints(URI.create("https://manual.issuer.example"));
        when(support.completeOAuthDance(any(), any(), any(), any()))
                .thenThrow(new RuntimeException("dance boom"));

        ConnectAttempt attempt = ConnectAttempt.withOauth(
                ENDPOINT, TransportType.STREAMABLE_HTTP, HOST, ServerConfigPanel.AUTH_OAUTH, hints, URI.create(ENDPOINT));

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
                ENDPOINT, TransportType.STREAMABLE_HTTP, HOST, ServerConfigPanel.AUTH_OAUTH, hints, URI.create(ENDPOINT));

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
                ENDPOINT, TransportType.STREAMABLE_HTTP, HOST, ServerConfigPanel.AUTH_OAUTH, hints, URI.create(ENDPOINT));

        Runnable terminalCallback = () -> {};
        coordinator.connect(attempt, (phase, message) -> {}, terminalCallback);

        verify(strategy).setTerminalFailureListener(terminalCallback);
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
