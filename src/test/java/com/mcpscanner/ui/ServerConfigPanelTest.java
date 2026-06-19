package com.mcpscanner.ui;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.CustomHeaderAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.OAuthTokens;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.auth.oauth.discovery.DiscoverySource;
import com.mcpscanner.auth.oauth.discovery.OAuthMetadataDiscoverer;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.TestOAuthFlows;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

class ServerConfigPanelTest {

    private static final String TEST_ENDPOINT = "https://mcp.example.com/mcp";

    private final ServerConfigPanel panel = new ServerConfigPanel(
            TestOAuthFlows.recording());

    @Test
    void currentAuthStrategyReturnsNoAuthWhenNoneSelected() {
        panel.showAuthCard(ServerConfigPanel.AUTH_NONE);

        AuthStrategy strategy = panel.currentAuthStrategy();

        assertThat(strategy).isInstanceOf(NoAuthStrategy.class);
    }

    @Test
    void currentAuthStrategyReturnsBearerTokenWhenBearerSelected() {
        panel.getTokenField().setText("my-secret-token");
        panel.showAuthCard(ServerConfigPanel.AUTH_BEARER);

        AuthStrategy strategy = panel.currentAuthStrategy();

        assertThat(strategy).isInstanceOf(BearerTokenAuthStrategy.class);
        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer my-secret-token");
    }

    @Test
    void currentAuthStrategyReturnsCustomHeadersWhenCustomSelected() {
        panel.getHeaderTablePanel().setHeaders(Map.of(
                "X-Api-Key", "abc123",
                "X-Custom", "value"));
        panel.showAuthCard(ServerConfigPanel.AUTH_CUSTOM);

        AuthStrategy strategy = panel.currentAuthStrategy();

        assertThat(strategy).isInstanceOf(CustomHeaderAuthStrategy.class);
        assertThat(strategy.headers())
                .containsEntry("X-Api-Key", "abc123")
                .containsEntry("X-Custom", "value");
    }

    @Test
    void clearOauthStrategyMakesCurrentAuthStrategyFailLoudEvenAfterPriorSuccess() {
        OAuthAuthCodeStrategy stale = new OAuthAuthCodeStrategy(
                URI.create("https://issuer.example.com"),
                List.of(),
                "client-id",
                null,
                null,
                new OAuthTokens(new BearerAccessToken("stale-token"),
                        new RefreshToken("rt"),
                        Instant.now().plusSeconds(600),
                        "alice"),
                (issuer, id, secret, rt, resource) -> {
                    throw new UnsupportedOperationException("not used");
                },
                Clock.systemUTC(),
                new McpEventLog(null));
        panel.setOauthStrategyForTest(stale);
        panel.showAuthCard(ServerConfigPanel.AUTH_OAUTH);
        assertThat(panel.currentAuthStrategy()).isSameAs(stale);

        panel.clearOauthStrategy();

        assertThatThrownBy(panel::currentAuthStrategy)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("OAuth selected but no authorization strategy has been established");
        assertThat(panel.currentOauthStrategy()).isNull();
    }

    @Test
    void currentAuthStrategyForCustomDropsWhitespaceOnlyKeyUpstream() {
        Map<String, String> raw = new LinkedHashMap<>();
        raw.put("   ", "value");
        raw.put("X-Real", "real-value");
        panel.getHeaderTablePanel().setHeaders(raw);
        panel.showAuthCard(ServerConfigPanel.AUTH_CUSTOM);

        AuthStrategy strategy = panel.currentAuthStrategy();

        assertThat(strategy).isInstanceOf(CustomHeaderAuthStrategy.class);
        assertThat(strategy.headers()).hasSize(1).containsEntry("X-Real", "real-value");
    }

    @Test
    void currentAuthStrategyForCustomThrowsWhenHeaderHasCrlf() {
        panel.getHeaderTablePanel().setHeaders(Map.of("X-Bad", "v\r\nInjected: yes"));
        panel.showAuthCard(ServerConfigPanel.AUTH_CUSTOM);

        assertThatThrownBy(panel::currentAuthStrategy)
                .isInstanceOf(IllegalArgumentException.class);
    }

    // --- Card switching ---

    @Test
    void showAuthCardSelectsOauthCardWhenOauthChosen() {
        panel.showAuthCard(ServerConfigPanel.AUTH_OAUTH);

        assertThat(panel.getDiscoverButton().getParent()).isNotNull();
    }

    @Test
    void noneCardShowsExplanatoryMessage() {
        panel.showAuthCard(ServerConfigPanel.AUTH_NONE);

        assertThat(visibleAuthCardLabels(panel))
                .containsExactly(ServerConfigPanel.AUTH_NONE_MESSAGE);
    }

    @Test
    void switchingAwayFromNoneHidesExplanatoryMessage() {
        panel.showAuthCard(ServerConfigPanel.AUTH_NONE);
        panel.showAuthCard(ServerConfigPanel.AUTH_BEARER);

        assertThat(visibleAuthCardLabels(panel))
                .doesNotContain(ServerConfigPanel.AUTH_NONE_MESSAGE);
    }

    private static List<String> visibleAuthCardLabels(ServerConfigPanel panel) {
        return java.util.Arrays.stream(panel.getAuthCardPanel().getComponents())
                .filter(java.awt.Component::isVisible)
                .flatMap(card -> java.util.Arrays.stream(((java.awt.Container) card).getComponents()))
                .filter(child -> child instanceof javax.swing.JLabel)
                .map(child -> ((javax.swing.JLabel) child).getText())
                .toList();
    }

    // --- Delegation coverage: ServerConfigPanel forwards OAuth calls to OAuthConfigPanel ---

    private static OAuthClientHints sampleHints() {
        return new OAuthClientHints(
                URI.create("https://issuer.example"),
                List.of("read"),
                "client-id",
                null,
                true,
                33418,
                Duration.ofSeconds(120));
    }

    private static OAuthConfigPanel spyOauthPanel() {
        return spy(new OAuthConfigPanel(
                TestOAuthFlows.recording(),
                new OAuthDiscoveryPresenter(mock(OAuthMetadataDiscoverer.class))));
    }

    @Test
    void delegatesBuildOauthHintsSnapshotToOauthPanel() {
        OAuthConfigPanel spyOauth = spyOauthPanel();
        OAuthClientHints hints = sampleHints();
        doReturn(hints).when(spyOauth).buildOauthHintsSnapshot();
        ServerConfigPanel host = new ServerConfigPanel(spyOauth);

        assertThat(host.buildOauthHintsSnapshot()).isSameAs(hints);
        verify(spyOauth).buildOauthHintsSnapshot();
    }

    @Test
    void delegatesCompleteOAuthDanceToOauthPanel() {
        OAuthConfigPanel spyOauth = spyOauthPanel();
        OAuthAuthCodeStrategy strategy = mock(OAuthAuthCodeStrategy.class);
        OAuthClientHints hints = sampleHints();
        URI resource = URI.create(TEST_ENDPOINT);
        McpEventLog log = new McpEventLog(null);
        doReturn(strategy).when(spyOauth).completeOAuthDance(hints, resource, log);
        ServerConfigPanel host = new ServerConfigPanel(spyOauth);

        assertThat(host.completeOAuthDance(hints, resource, log)).isSameAs(strategy);
        verify(spyOauth).completeOAuthDance(hints, resource, log);
    }

    @Test
    void delegatesDiscoverApplyPublishClearToOauthPanel() throws Exception {
        OAuthConfigPanel spyOauth = spyOauthPanel();
        DiscoveredMetadata metadata = new DiscoveredMetadata(
                URI.create("https://issuer.example"),
                DiscoverySource.AS_WELL_KNOWN,
                mock(AuthorizationServerMetadata.class));
        doReturn(metadata).when(spyOauth).discoverOauthMetadataSync(TEST_ENDPOINT);
        OAuthAuthCodeStrategy strategy = mock(OAuthAuthCodeStrategy.class);
        ServerConfigPanel host = new ServerConfigPanel(spyOauth);

        assertThat(host.discoverOauthMetadataSync(TEST_ENDPOINT)).isSameAs(metadata);
        host.applyDiscoveredMetadata(metadata);
        host.publishOauthStrategy(strategy);
        host.clearOauthStrategy();
        host.clearAutoDiscoveredOAuth();

        verify(spyOauth).discoverOauthMetadataSync(TEST_ENDPOINT);
        verify(spyOauth).applyDiscoveredMetadata(metadata);
        verify(spyOauth).publishOauthStrategy(strategy);
        verify(spyOauth).clearOauthStrategy();
        verify(spyOauth).clearAutoDiscoveredOAuth();
    }

    @Test
    void delegatesBuildConnectedStatusAndCurrentStrategyToOauthPanel() {
        OAuthConfigPanel spyOauth = spyOauthPanel();
        OAuthAuthCodeStrategy strategy = mock(OAuthAuthCodeStrategy.class);
        doReturn(strategy).when(spyOauth).currentOauthStrategy();
        ServerConfigPanel host = new ServerConfigPanel(spyOauth);

        host.buildConnectedStatus("host", 3);
        assertThat(host.currentOauthStrategy()).isSameAs(strategy);

        verify(spyOauth).buildConnectedStatus("host", 3);
        verify(spyOauth).currentOauthStrategy();
    }

    @Test
    void configurationLockForwardsToOauthPanel() {
        OAuthConfigPanel spyOauth = spyOauthPanel();
        ServerConfigPanel host = new ServerConfigPanel(spyOauth);

        host.setConfigurationLocked(true);

        verify(spyOauth).setConfigurationLocked(true);
    }

    @Test
    void endpointSupplierAndChangeForwardToOauthPanel() {
        OAuthConfigPanel spyOauth = spyOauthPanel();
        ServerConfigPanel host = new ServerConfigPanel(spyOauth);
        java.util.function.Supplier<String> supplier = () -> "x";

        host.setEndpointSupplier(supplier);
        host.onEndpointChanged();

        verify(spyOauth).setEndpointSupplier(supplier);
        verify(spyOauth).onEndpointChanged();
    }
}
