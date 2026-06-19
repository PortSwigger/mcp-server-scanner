package com.mcpscanner.ui;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.OAuthAuthorizationFlow;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.OAuthSession;
import com.mcpscanner.auth.oauth.OAuthTokens;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.auth.oauth.discovery.DiscoveryFailedException;
import com.mcpscanner.auth.oauth.discovery.DiscoverySource;
import com.mcpscanner.auth.oauth.discovery.OAuthMetadataDiscoverer;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.TestOAuthFlows;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.awt.Color;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OAuthConfigPanelTest {

    private static final String TEST_ENDPOINT = "https://mcp.example.com/mcp";

    private final OAuthConfigPanel panel = newPanel(TestOAuthFlows.recording(), mock(OAuthMetadataDiscoverer.class));

    private static OAuthConfigPanel newPanel(OAuthAuthorizationFlow flow, OAuthMetadataDiscoverer discoverer) {
        return new OAuthConfigPanel(flow, new OAuthDiscoveryPresenter(discoverer));
    }

    private static OAuthConfigPanel newPanelWithStore(
            ExtensionConfigStore configStore, OAuthMetadataDiscoverer discoverer) {
        OAuthConfigPanel panel = newPanel(TestOAuthFlows.recording(), discoverer);
        panel.bindConfigStore(configStore);
        return panel;
    }

    @Test
    void completeOAuthDanceReturnsStrategyButDoesNotPublishItOffEdt() {
        OAuthAuthorizationFlow authorizationFlow = mock(OAuthAuthorizationFlow.class);
        OAuthTokens tokens = new OAuthTokens(
                new BearerAccessToken("access"),
                new RefreshToken("refresh"),
                Instant.now().plusSeconds(600),
                "alice");
        when(authorizationFlow.connect(any(), any()))
                .thenReturn(OAuthSession.withoutDcrCredentials(tokens, "client-id", null));
        OAuthConfigPanel uut = newPanel(authorizationFlow, mock(OAuthMetadataDiscoverer.class));

        OAuthClientHints snapshot = new OAuthClientHints(
                URI.create("https://issuer.example"),
                java.util.List.of("read"),
                "client-id",
                null,
                true,
                33418,
                Duration.ofSeconds(120));

        OAuthAuthCodeStrategy strategy = uut.completeOAuthDance(snapshot, URI.create(TEST_ENDPOINT), new McpEventLog(null));

        assertThat(strategy).isNotNull();
        assertThat(uut.currentOauthStrategy()).isNull();
    }

    @Test
    void publishOauthStrategyOnEdtMakesItCurrent() throws Exception {
        OAuthAuthorizationFlow authorizationFlow = mock(OAuthAuthorizationFlow.class);
        OAuthTokens tokens = new OAuthTokens(
                new BearerAccessToken("access"),
                new RefreshToken("refresh"),
                Instant.now().plusSeconds(600),
                "alice");
        when(authorizationFlow.connect(any(), any()))
                .thenReturn(OAuthSession.withoutDcrCredentials(tokens, "client-id", null));
        OAuthConfigPanel uut = newPanel(authorizationFlow, mock(OAuthMetadataDiscoverer.class));

        OAuthClientHints snapshot = new OAuthClientHints(
                URI.create("https://issuer.example"),
                java.util.List.of("read"),
                "client-id",
                null,
                true,
                33418,
                Duration.ofSeconds(120));

        OAuthAuthCodeStrategy strategy = uut.completeOAuthDance(snapshot, URI.create(TEST_ENDPOINT), new McpEventLog(null));
        invokeAndWait(() -> uut.publishOauthStrategy(strategy));

        assertThat(uut.currentOauthStrategy()).isSameAs(strategy);
    }

    @Test
    void discoverAutoFillsIssuerAndUpdatesStatusOnSuccess() throws Exception {
        DiscoveredMetadata metadata = new DiscoveredMetadata(
                URI.create("https://issuer.example"),
                DiscoverySource.AS_WELL_KNOWN,
                mock(AuthorizationServerMetadata.class));
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        when(discoverer.discover(URI.create(TEST_ENDPOINT))).thenReturn(metadata);

        OAuthConfigPanel uut = newPanel(TestOAuthFlows.recording(), discoverer);

        triggerDiscoverAndSettle(uut, TEST_ENDPOINT);

        assertThat(uut.getOauthIssuerField().getText()).isEqualTo("https://issuer.example");
        assertThat(uut.getDiscoveryStatusLabel().getText())
                .contains(DiscoverySource.AS_WELL_KNOWN.displayPath());
    }

    @Test
    void discoverShowsRedFailureMessageWhenDiscoveryFails() throws Exception {
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        when(discoverer.discover(URI.create(TEST_ENDPOINT)))
                .thenThrow(new DiscoveryFailedException("nope"));

        OAuthConfigPanel uut = newPanel(TestOAuthFlows.recording(), discoverer);
        uut.getOauthIssuerField().setText("https://prior.example");

        triggerDiscoverAndSettle(uut, TEST_ENDPOINT);

        assertThat(uut.getOauthIssuerField().getText()).isEqualTo("https://prior.example");
        assertThat(uut.getDiscoveryStatusLabel().getText()).contains("No OAuth metadata found");
        assertThat(uut.getDiscoveryStatusLabel().getForeground()).isEqualTo(Color.RED);
    }

    @Test
    void discoveryOverwritesManualIssuer() throws Exception {
        DiscoveredMetadata metadata = new DiscoveredMetadata(
                URI.create("https://issuer.example"),
                DiscoverySource.AS_WELL_KNOWN,
                mock(AuthorizationServerMetadata.class));
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        when(discoverer.discover(URI.create(TEST_ENDPOINT))).thenReturn(metadata);

        OAuthConfigPanel uut = newPanel(TestOAuthFlows.recording(), discoverer);
        uut.getOauthIssuerField().setText("https://manually-typed.example");

        triggerDiscoverAndSettle(uut, TEST_ENDPOINT);

        assertThat(uut.getOauthIssuerField().getText()).isEqualTo("https://issuer.example");
        assertThat(uut.getDiscoveryStatusLabel().getText())
                .contains(DiscoverySource.AS_WELL_KNOWN.displayPath());
    }

    @Test
    void discoverShowsInlineErrorForInvalidEndpointUrl() throws Exception {
        OAuthConfigPanel uut = newPanel(TestOAuthFlows.recording(), mock(OAuthMetadataDiscoverer.class));

        uut.discoverOauthMetadata("not a url");
        invokeAndWait(() -> {});

        assertThat(uut.getDiscoveryStatusLabel().getText()).containsIgnoringCase("invalid");
        assertThat(uut.getDiscoveryStatusLabel().getForeground()).isEqualTo(Color.RED);
    }

    @Test
    void discoveryFlowsScopesIntoBuiltHints() throws Exception {
        AuthorizationServerMetadata advertisedMetadata = mock(AuthorizationServerMetadata.class);
        when(advertisedMetadata.getScopes()).thenReturn(new Scope("read", "write"));
        DiscoveredMetadata metadata = new DiscoveredMetadata(
                URI.create("https://issuer.example"),
                DiscoverySource.AS_WELL_KNOWN,
                advertisedMetadata);
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        when(discoverer.discover(URI.create(TEST_ENDPOINT))).thenReturn(metadata);

        OAuthAuthorizationFlow authorizationFlow = mock(OAuthAuthorizationFlow.class);
        OAuthTokens tokens = new OAuthTokens(
                new BearerAccessToken("access"),
                new RefreshToken("refresh"),
                Instant.now().plusSeconds(600),
                "alice");
        when(authorizationFlow.connect(any(), any()))
                .thenReturn(OAuthSession.withoutDcrCredentials(tokens, "client-id", null));

        OAuthConfigPanel uut = newPanel(authorizationFlow, discoverer);
        uut.setOauthSelected(true);

        triggerDiscoverAndSettle(uut, TEST_ENDPOINT);

        assertThat(uut.scopeTablePanelForTest().enabledScopes()).containsExactlyInAnyOrder("read", "write");

        AtomicReference<OAuthClientHints> hintsRef = new AtomicReference<>();
        invokeAndWait(() -> hintsRef.set(uut.buildOauthHintsSnapshot()));
        OAuthAuthCodeStrategy strategy = uut.completeOAuthDance(hintsRef.get(), URI.create(TEST_ENDPOINT),
                new McpEventLog(null));
        invokeAndWait(() -> uut.publishOauthStrategy(strategy));

        assertThat(uut.currentOauthStrategy()).isSameAs(strategy);
        assertThat(strategy.scopes()).containsExactlyInAnyOrder("read", "write");
    }

    @Test
    void buildOauthHintsAllowsEmptyIssuer() {
        panel.getOauthIssuerField().setText("");
        panel.setOauthSelected(true);

        OAuthClientHints hints = panel.buildOauthHintsSnapshot();

        assertThat(hints.issuer()).isNull();
    }

    @Test
    void buildOauthHintsStillRequiresClientIdWhenSkipDcr() {
        panel.getOauthIssuerField().setText("");
        panel.getOauthSkipDcrCheckbox().setSelected(true);
        panel.getOauthClientIdField().setText("");
        panel.setOauthSelected(true);

        assertThatThrownBy(panel::buildOauthHintsSnapshot)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Client ID");
    }

    @Test
    void oauthStrategyFieldIsVolatile() throws Exception {
        java.lang.reflect.Field f = OAuthConfigPanel.class.getDeclaredField("oauthStrategy");
        assertThat(java.lang.reflect.Modifier.isVolatile(f.getModifiers())).isTrue();
    }

    @Test
    void clearAutoDiscoveredOAuthWipesIssuerAndClearsConfigKeyWhenAutoDiscovered() throws Exception {
        PersistedObject store = mock(PersistedObject.class);
        when(store.getBoolean(anyString())).thenReturn(null);
        ExtensionConfigStore configStore = new ExtensionConfigStore(store, mock(Logging.class));
        DiscoveredMetadata metadata = new DiscoveredMetadata(
                URI.create("https://issuer.example"),
                DiscoverySource.AS_WELL_KNOWN,
                mock(AuthorizationServerMetadata.class));
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        when(discoverer.discover(URI.create(TEST_ENDPOINT))).thenReturn(metadata);

        AtomicReference<OAuthConfigPanel> ref = new AtomicReference<>();
        invokeAndWait(() -> ref.set(newPanelWithStore(configStore, discoverer)));
        OAuthConfigPanel uut = ref.get();

        triggerDiscoverAndSettle(uut, TEST_ENDPOINT);
        invokeAndWait(uut::clearAutoDiscoveredOAuth);

        assertThat(uut.getOauthIssuerField().getText()).isEmpty();
        verify(store, atLeastOnce()).setString("mcp.oauth.issuer", "");
    }

    @Test
    void clearAutoDiscoveredOAuthLeavesUserTypedIssuerIntact() throws Exception {
        PersistedObject store = mock(PersistedObject.class);
        when(store.getBoolean(anyString())).thenReturn(null);
        ExtensionConfigStore configStore = new ExtensionConfigStore(store, mock(Logging.class));

        AtomicReference<OAuthConfigPanel> ref = new AtomicReference<>();
        invokeAndWait(() -> ref.set(newPanelWithStore(configStore, mock(OAuthMetadataDiscoverer.class))));
        OAuthConfigPanel uut = ref.get();

        invokeAndWait(() -> uut.getOauthIssuerField().setText("https://user-typed.example"));
        invokeAndWait(uut::clearAutoDiscoveredOAuth);

        assertThat(uut.getOauthIssuerField().getText()).isEqualTo("https://user-typed.example");
    }

    @Test
    void discoveryDoesNotPersistIssuer() throws Exception {
        PersistedObject store = mock(PersistedObject.class);
        when(store.getBoolean(anyString())).thenReturn(null);
        ExtensionConfigStore configStore = new ExtensionConfigStore(store, mock(Logging.class));
        DiscoveredMetadata metadata = new DiscoveredMetadata(
                URI.create("https://issuer.example"),
                DiscoverySource.AS_WELL_KNOWN,
                mock(AuthorizationServerMetadata.class));
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        when(discoverer.discover(URI.create(TEST_ENDPOINT))).thenReturn(metadata);

        AtomicReference<OAuthConfigPanel> ref = new AtomicReference<>();
        invokeAndWait(() -> ref.set(newPanelWithStore(configStore, discoverer)));
        OAuthConfigPanel uut = ref.get();

        triggerDiscoverAndSettle(uut, TEST_ENDPOINT);

        verify(store, never()).setString("mcp.oauth.issuer", "https://issuer.example");
    }

    @Test
    void userEditAfterDiscoveryClearsAutoFlagAndPersists() throws Exception {
        PersistedObject store = mock(PersistedObject.class);
        when(store.getBoolean(anyString())).thenReturn(null);
        ExtensionConfigStore configStore = new ExtensionConfigStore(store, mock(Logging.class));
        DiscoveredMetadata metadata = new DiscoveredMetadata(
                URI.create("https://issuer.example"),
                DiscoverySource.AS_WELL_KNOWN,
                mock(AuthorizationServerMetadata.class));
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        when(discoverer.discover(URI.create(TEST_ENDPOINT))).thenReturn(metadata);

        AtomicReference<OAuthConfigPanel> ref = new AtomicReference<>();
        invokeAndWait(() -> ref.set(newPanelWithStore(configStore, discoverer)));
        OAuthConfigPanel uut = ref.get();

        triggerDiscoverAndSettle(uut, TEST_ENDPOINT);
        invokeAndWait(() -> uut.getOauthIssuerField().setText("https://user-edited.example"));
        invokeAndWait(uut::clearAutoDiscoveredOAuth);

        assertThat(uut.getOauthIssuerField().getText()).isEqualTo("https://user-edited.example");
        verify(store, atLeastOnce()).setString("mcp.oauth.issuer", "https://user-edited.example");
    }

    @Test
    void clearAutoDiscoveredOAuthIsIdempotent() throws Exception {
        PersistedObject store = mock(PersistedObject.class);
        when(store.getBoolean(anyString())).thenReturn(null);
        ExtensionConfigStore configStore = new ExtensionConfigStore(store, mock(Logging.class));

        AtomicReference<OAuthConfigPanel> ref = new AtomicReference<>();
        invokeAndWait(() -> ref.set(newPanelWithStore(configStore, mock(OAuthMetadataDiscoverer.class))));
        OAuthConfigPanel uut = ref.get();

        invokeAndWait(uut::clearAutoDiscoveredOAuth);
        invokeAndWait(uut::clearAutoDiscoveredOAuth);

        assertThat(uut.getOauthIssuerField().getText()).isEmpty();
    }

    private static void triggerDiscoverAndSettle(OAuthConfigPanel uut, String endpoint) throws Exception {
        invokeAndWait(() -> uut.discoverOauthMetadata(endpoint));
        await().atMost(ofSeconds(5))
                .until(() -> !isTransientDiscoveryStatus(uut.getDiscoveryStatusLabel().getText()));
    }

    private static boolean isTransientDiscoveryStatus(String label) {
        return label == null || label.isBlank() || label.equals("Discovering...");
    }

    private static void invokeAndWait(Runnable r) throws InterruptedException, InvocationTargetException {
        if (SwingUtilities.isEventDispatchThread()) {
            r.run();
        } else {
            SwingUtilities.invokeAndWait(r);
        }
    }
}
