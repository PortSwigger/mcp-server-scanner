package com.mcpscanner.ui;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.OAuthAuthorizationFlow;
import com.mcpscanner.auth.grant.ClientType;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.auth.oauth.OAuthSession;
import com.mcpscanner.auth.oauth.SharedOAuthSession;
import com.mcpscanner.auth.oauth.OAuthTokens;
import com.mcpscanner.auth.oauth.discovery.DiscoveredMetadata;
import com.mcpscanner.auth.oauth.discovery.DiscoveryFailedException;
import com.mcpscanner.auth.oauth.discovery.DiscoverySource;
import com.mcpscanner.auth.oauth.discovery.OAuthMetadataDiscoverer;
import com.mcpscanner.config.ExtensionConfigStore;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.TestOAuthFlows;
import com.nimbusds.oauth2.sdk.Scope;
import com.mcpscanner.core.oauth.RegistrationMode;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.awt.Color;
import java.lang.reflect.InvocationTargetException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static java.time.Duration.ofSeconds;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OAuthConfigPanelTest {

    private static final String TEST_ENDPOINT = "https://mcp.example.com/mcp";

    private final OAuthConfigPanel panel = newPanel(TestOAuthFlows.recording(), mock(OAuthMetadataDiscoverer.class));

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "AUTO, true, true",
            "PRE_REGISTERED, true, false",
            "CIMD, false, true",
            "DCR, false, false"})
    void registrationModeShowsOnlyTheFieldsItUsesAndStatesWhatIsRequired(
            RegistrationMode mode, boolean showsClient, boolean showsMetadataUrl) {
        panel.getRegistrationModeSelector().setSelectedItem(mode);

        assertThat(panel.getOauthClientIdField().isVisible()).isEqualTo(showsClient);
        assertThat(panel.getClientMetadataUrlField().isVisible()).isEqualTo(showsMetadataUrl);
        assertThat(com.mcpscanner.testutil.SwingTree.descendants(panel))
                .filteredOn(com.mcpscanner.ui.widgets.WrappingText.class::isInstance)
                .extracting(text -> ((com.mcpscanner.ui.widgets.WrappingText) text).getText())
                .contains(RegistrationModeText.requirement(mode))
                .noneMatch(text -> text != null && text.contains("<html>"));
    }

    @Test
    void preRegisteredWithoutClientIdBlocksConnectAndMarksTheClientIdRequired() {
        panel.getRegistrationModeSelector().setSelectedItem(RegistrationMode.PRE_REGISTERED);

        assertThat(panel.validatedHints().problem()).hasValueSatisfying(reason -> assertThat(reason).contains("Client ID is required"));
        assertThat(visibleMarkers(panel)).isEqualTo(1);
    }

    @Test
    void cimdWithoutMetadataUrlBlocksConnectAndMarksUrlAndPortRequired() {
        panel.getRegistrationModeSelector().setSelectedItem(RegistrationMode.CIMD);

        assertThat(panel.validatedHints().problem()).hasValueSatisfying(reason -> assertThat(reason).contains("Metadata URL"));
        assertThat(visibleMarkers(panel)).isEqualTo(2);
    }

    @Test
    void dcrNeedsNothingAndShowsNoRequiredMarkers() {
        panel.getRegistrationModeSelector().setSelectedItem(RegistrationMode.DCR);

        assertThat(panel.validatedHints().problem()).isEmpty();
        assertThat(panel.validatedHints().value()).isPresent();
        assertThat(visibleMarkers(panel)).isZero();
    }

    @Test
    void changeListenerFiresWhenTheRegistrationModeChanges() {
        var changes = new java.util.concurrent.atomic.AtomicInteger();
        panel.setChangeListener(changes::incrementAndGet);

        panel.getRegistrationModeSelector().setSelectedItem(RegistrationMode.PRE_REGISTERED);

        assertThat(changes.get()).isPositive();
    }

    @Test
    void autoModeTellsTheUserWhenASavedClientIdWillBeIgnored() {
        PersistedObject store = mock(PersistedObject.class);
        when(store.getBoolean(anyString())).thenReturn(null);
        when(store.getString("mcp.oauth.client_id")).thenReturn("saved-client");
        OAuthConfigPanel uut = newPanelWithStore(new ExtensionConfigStore(store, mock(Logging.class)),
                mock(OAuthMetadataDiscoverer.class));

        assertThat(com.mcpscanner.testutil.SwingTree.visibleDescendants(uut))
                .filteredOn(com.mcpscanner.ui.widgets.WrappingText.class::isInstance)
                .extracting(text -> ((com.mcpscanner.ui.widgets.WrappingText) text).getText())
                .anyMatch(text -> text.contains("Client ID is ignored"));
    }

    @Test
    void beginningASignInAttemptRunsTheGivenAttemptStart() {
        java.util.concurrent.atomic.AtomicInteger attemptsStarted = new java.util.concurrent.atomic.AtomicInteger();
        OAuthConfigPanel withAttemptStart = new OAuthConfigPanel(TestOAuthFlows.recording(),
                new OAuthDiscoveryPresenter(mock(OAuthMetadataDiscoverer.class)), attemptsStarted::incrementAndGet,
                TestDialogOwners.withoutSuiteFrame());

        withAttemptStart.beginSignInAttempt();

        assertThat(attemptsStarted).hasValue(1);
    }

    private static long visibleMarkers(java.awt.Container root) {
        return com.mcpscanner.testutil.SwingTree.descendants(root).stream()
                .filter(javax.swing.JLabel.class::isInstance).map(javax.swing.JLabel.class::cast)
                .filter(label -> com.mcpscanner.ui.widgets.LabeledForm.REQUIRED_MARKER.equals(label.getText()))
                .filter(java.awt.Component::isVisible).count();
    }

    private static OAuthConfigPanel newPanel(OAuthAuthorizationFlow flow, OAuthMetadataDiscoverer discoverer) {
        return new OAuthConfigPanel(flow, new OAuthDiscoveryPresenter(discoverer),
                TestDialogOwners.withoutSuiteFrame());
    }

    private static OAuthConfigPanel newPanelWithStore(
            ExtensionConfigStore configStore, OAuthMetadataDiscoverer discoverer) {
        OAuthConfigPanel panel = newPanel(TestOAuthFlows.recording(), discoverer);
        panel.bindConfigStore(configStore);
        return panel;
    }

    @Test
    void applyingDiscoveredMetadataUsesSelectedResourceScopes() throws Exception {
        AuthorizationServerMetadata metadata = mock(AuthorizationServerMetadata.class);
        when(metadata.getScopes()).thenReturn(new Scope("admin"));
        DiscoveredMetadata discovered = new DiscoveredMetadata(URI.create("https://issuer.example"),
                DiscoverySource.WWW_AUTHENTICATE_HEADER, metadata, java.util.List.of("files:read"));

        invokeAndWait(() -> panel.applyDiscoveredMetadata(discovered));

        assertThat(panel.buildOauthHintsSnapshot().scopes()).containsExactly("files:read");
    }

    @Test
    void completeOAuthDanceReturnsStrategyButDoesNotPublishItOffEdt() {
        OAuthAuthorizationFlow authorizationFlow = mock(OAuthAuthorizationFlow.class);
        OAuthTokens tokens = new OAuthTokens(
                new BearerAccessToken("access"),
                new RefreshToken("refresh"),
                Instant.now().plusSeconds(600),
                "alice");
        when(authorizationFlow.connect(any(), any(), any()))
                .thenReturn(new OAuthSession(tokens, "client-id", null, java.util.Optional.empty(), java.util.Optional.empty(),
                        mock(com.mcpscanner.auth.oauth.SharedOAuthSession.class)));
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
    void completedDanceAdvertisesTheRegistrationEndpointItsSessionResolved() {
        OAuthAuthorizationFlow authorizationFlow = mock(OAuthAuthorizationFlow.class);
        URI registration = URI.create("https://issuer.example/register");
        OAuthTokens tokens = new OAuthTokens(new BearerAccessToken("access"), null,
                Instant.now().plusSeconds(600), "alice");
        when(authorizationFlow.connect(any(), any(), any())).thenReturn(new OAuthSession(tokens, "client-id", null,
                Optional.empty(), Optional.empty(), mock(SharedOAuthSession.class), null, Optional.of(registration)));
        OAuthConfigPanel uut = newPanel(authorizationFlow, mock(OAuthMetadataDiscoverer.class));
        OAuthClientHints snapshot = new OAuthClientHints(URI.create("https://issuer.example"), java.util.List.of(),
                null, null, true, 33418, Duration.ofSeconds(120));

        assertThat(uut.authorizationServerOfLastDance().registrationEndpoint()).isEmpty();
        uut.completeOAuthDance(snapshot, URI.create(TEST_ENDPOINT), new McpEventLog(null));

        assertThat(uut.authorizationServerOfLastDance().registrationEndpoint()).contains(registration);
    }

    @Test
    void publishOauthStrategyOnEdtMakesItCurrent() throws Exception {
        OAuthAuthorizationFlow authorizationFlow = mock(OAuthAuthorizationFlow.class);
        OAuthTokens tokens = new OAuthTokens(
                new BearerAccessToken("access"),
                new RefreshToken("refresh"),
                Instant.now().plusSeconds(600),
                "alice");
        when(authorizationFlow.connect(any(), any(), any()))
                .thenReturn(new OAuthSession(tokens, "client-id", null, java.util.Optional.empty(), java.util.Optional.empty(),
                        mock(com.mcpscanner.auth.oauth.SharedOAuthSession.class)));
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
        assertThat(uut.getDiscoveryStatusLabel().getForeground()).isEqualTo(com.mcpscanner.ui.widgets.ThemeColors.error());
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
        assertThat(uut.getDiscoveryStatusLabel().getForeground()).isEqualTo(com.mcpscanner.ui.widgets.ThemeColors.error());
    }

    @Test
    void discoveryFlowsScopesIntoBuiltHints() throws Exception {
        AuthorizationServerMetadata advertisedMetadata = mock(AuthorizationServerMetadata.class);
        when(advertisedMetadata.getScopes()).thenReturn(new Scope("admin"));
        DiscoveredMetadata metadata = new DiscoveredMetadata(
                URI.create("https://issuer.example"),
                DiscoverySource.AS_WELL_KNOWN,
                advertisedMetadata, java.util.List.of("read", "write"));
        OAuthMetadataDiscoverer discoverer = mock(OAuthMetadataDiscoverer.class);
        when(discoverer.discover(URI.create(TEST_ENDPOINT))).thenReturn(metadata);

        OAuthAuthorizationFlow authorizationFlow = mock(OAuthAuthorizationFlow.class);
        OAuthTokens tokens = new OAuthTokens(
                new BearerAccessToken("access"),
                new RefreshToken("refresh"),
                Instant.now().plusSeconds(600),
                "alice");
        var sharedSession = mock(com.mcpscanner.auth.oauth.SharedOAuthSession.class);
        when(sharedSession.requestedScopes()).thenReturn(java.util.Set.of("read", "write"));
        when(authorizationFlow.connect(any(), any(), any()))
                .thenReturn(new OAuthSession(tokens, "client-id", null, java.util.Optional.empty(), java.util.Optional.empty(),
                        sharedSession));

        OAuthConfigPanel uut = newPanel(authorizationFlow, discoverer);

        triggerDiscoverAndSettle(uut, TEST_ENDPOINT);

        assertThat(uut.buildOauthHintsSnapshot().scopes()).containsExactlyInAnyOrder("read", "write");

        AtomicReference<OAuthClientHints> hintsRef = new AtomicReference<>();
        invokeAndWait(() -> hintsRef.set(uut.buildOauthHintsSnapshot()));
        OAuthAuthCodeStrategy strategy = uut.completeOAuthDance(hintsRef.get(), URI.create(TEST_ENDPOINT),
                new McpEventLog(null));
        invokeAndWait(() -> uut.publishOauthStrategy(strategy));

        assertThat(uut.currentOauthStrategy()).isSameAs(strategy);
        assertThat(strategy.requestedScopes()).containsExactlyInAnyOrder("read", "write");
    }

    @Test
    void cimdSettingsSurviveReloadAndOverrideLegacyChoice() {
        Map<String, Object> values = new HashMap<>();
        values.put("mcp.oauth.skip_dcr", true);
        values.put("mcp.oauth.issuer", "https://issuer.example");
        values.put("mcp.oauth.client_id", "manual-client");
        ExtensionConfigStore store = statefulConfigStore(values);
        OAuthConfigPanel original = newPanelWithStore(store, mock(OAuthMetadataDiscoverer.class));
        assertThat(original.buildOauthHintsSnapshot().clientId()).isEqualTo("manual-client");
        original.getRegistrationModeSelector().setSelectedItem(RegistrationMode.CIMD);
        original.getClientMetadataUrlField().setText("https://client.example/metadata.json");
        original.getRedirectPortSpinner().setValue(8765);

        OAuthConfigPanel restored = newPanelWithStore(store, mock(OAuthMetadataDiscoverer.class));
        OAuthClientHints hints = restored.buildOauthHintsSnapshot();
        assertThat(hints.registrationMode()).isEqualTo(RegistrationMode.CIMD);
        assertThat(hints.clientMetadataUrl()).isEqualTo(URI.create("https://client.example/metadata.json"));
        assertThat(hints.redirectPort()).isEqualTo(8765);
        assertThat(hints.clientId()).isNull();
        assertThat(restored.getOauthClientIdField().getText()).isEqualTo("manual-client");
        assertThat(values).containsEntry("mcp.oauth.client_issuer", "https://issuer.example");
    }

    @Test
    void savedClientBindingStillRejectsChangedIssuerAfterReload() {
        Map<String, Object> values = new HashMap<>();
        ExtensionConfigStore store = statefulConfigStore(values);
        OAuthConfigPanel original = newPanelWithStore(store, mock(OAuthMetadataDiscoverer.class));
        original.getOauthIssuerField().setText("https://first.example");
        original.getOauthClientIdField().setText("client-first");
        original.getOauthIssuerField().setText("https://second.example");

        OAuthConfigPanel restored = newPanelWithStore(store, mock(OAuthMetadataDiscoverer.class));
        assertThatThrownBy(restored::buildOauthHintsSnapshot).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("issuer");
        restored.getOauthClientIdField().setText("client-second");
        assertThat(restored.buildOauthHintsSnapshot().clientId()).isEqualTo("client-second");
    }

    private static ExtensionConfigStore statefulConfigStore(Map<String, Object> values) {
        PersistedObject persisted = mock(PersistedObject.class);
        when(persisted.getString(anyString())).thenAnswer(call -> values.get(call.getArgument(0)));
        when(persisted.getBoolean(anyString())).thenAnswer(call -> values.get(call.getArgument(0)));
        when(persisted.getInteger(anyString())).thenAnswer(call -> values.get(call.getArgument(0)));
        doAnswer(call -> values.put(call.getArgument(0), call.getArgument(1)))
                .when(persisted).setString(anyString(), anyString());
        doAnswer(call -> values.put(call.getArgument(0), call.getArgument(1)))
                .when(persisted).setInteger(anyString(), org.mockito.ArgumentMatchers.anyInt());
        return new ExtensionConfigStore(persisted, mock(Logging.class));
    }

    @Test
    void lockingDisablesEveryOAuthClientInputAndUnlockingRestoresThem() {
        panel.getRegistrationModeSelector().setSelectedItem(RegistrationMode.PRE_REGISTERED);

        panel.setConfigurationLocked(true);

        assertThat(List.of(panel.getOauthIssuerField(), panel.getRegistrationModeSelector(),
                panel.getRedirectPortSpinner(), panel.getOauthClientIdField(), panel.scopeTable().table(),
                panel.getDiscoverButton())).noneMatch(java.awt.Component::isEnabled);

        panel.setConfigurationLocked(false);

        assertThat(List.of(panel.getOauthIssuerField(), panel.getRegistrationModeSelector(),
                panel.getRedirectPortSpinner(), panel.getOauthClientIdField(), panel.scopeTable().table()))
                .allMatch(java.awt.Component::isEnabled);
    }

    @Test
    void lockedInputsLookLockedBecauseTheirTextFades() {
        panel.setConfigurationLocked(true);

        assertThat(List.of(panel.getOauthIssuerField(), panel.getOauthClientIdField(),
                panel.getClientMetadataUrlField())).allSatisfy(field ->
                assertThat(field.getDisabledTextColor()).isNotEqualTo(field.getForeground()));
        javax.swing.JTable scopes = panel.scopeTable().table();
        assertThat(scopes.getForeground()).isNotEqualTo(javax.swing.UIManager.getColor("Table.foreground"));
        javax.swing.JTextField port = ((javax.swing.JSpinner.DefaultEditor) panel.getRedirectPortSpinner().getEditor())
                .getTextField();
        assertThat(port.getDisabledTextColor()).isNotEqualTo(port.getForeground());
        panel.scopeTable().seed(List.of(new ExtensionConfigStore.PersistedScope("custom:one", true, "custom")));
        java.awt.Component tick = scopes.prepareRenderer(scopes.getCellRenderer(0, ScopeTableModel.COLUMN_ENABLED),
                0, ScopeTableModel.COLUMN_ENABLED);
        assertThat(tick.isEnabled()).isFalse();

        panel.setConfigurationLocked(false);

        assertThat(scopes.getForeground()).isEqualTo(javax.swing.UIManager.getColor("Table.foreground"));
    }

    @Test
    void registrationInputsRespectModeAfterConfigurationUnlock() {
        panel.getRegistrationModeSelector().setSelectedItem(RegistrationMode.DCR);
        panel.setConfigurationLocked(true);
        panel.getOauthClientIdField().setEnabled(true);
        panel.getClientMetadataUrlField().setEnabled(true);
        panel.setConfigurationLocked(false);

        assertThat(panel.getOauthClientIdField().isEnabled()).isFalse();
        assertThat(panel.getClientMetadataUrlField().isEnabled()).isFalse();
    }

    @Test
    void oldDcrSettingsPreserveButDoNotActivateAnIgnoredClientId() {
        PersistedObject store = mock(PersistedObject.class);
        when(store.getString("mcp.oauth.issuer")).thenReturn("https://issuer.example");
        when(store.getString("mcp.oauth.client_id")).thenReturn("old-ignored-id");
        when(store.getBoolean("mcp.oauth.skip_dcr")).thenReturn(false);
        OAuthConfigPanel restored = newPanelWithStore(new ExtensionConfigStore(store, mock(Logging.class)),
                mock(OAuthMetadataDiscoverer.class));

        assertThat(restored.getOauthClientIdField().getText()).isEqualTo("old-ignored-id");
        OAuthClientHints hints = restored.buildOauthHintsSnapshot();
        assertThat(hints.registrationMode()).isEqualTo(RegistrationMode.AUTO);
        assertThat(hints.clientId()).isNull();
        restored.getOauthClientIdField().setText("new-client-id");
        assertThat(restored.buildOauthHintsSnapshot().clientId()).isEqualTo("new-client-id");
        verify(store, atLeastOnce()).setString("mcp.oauth.client_issuer", "https://issuer.example");
    }

    @Test
    void changedIssuerRequiresClientIdToBeReenteredBeforeReuse() {
        panel.getOauthIssuerField().setText("https://first.example");
        panel.getRegistrationModeSelector().setSelectedItem(RegistrationMode.PRE_REGISTERED);
        panel.getOauthClientIdField().setText("registered-client");
        assertThat(panel.buildOauthHintsSnapshot().clientId()).isEqualTo("registered-client");

        panel.getOauthIssuerField().setText("https://second.example");
        assertThatThrownBy(panel::buildOauthHintsSnapshot).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("issuer");

        panel.getOauthClientIdField().setText("client-for-second-issuer");
        assertThat(panel.buildOauthHintsSnapshot().clientId()).isEqualTo("client-for-second-issuer");
    }

    @Test
    void registrationModeSwitchingExposesOnlyApplicableInputsAndHints() {
        assertThat(panel.getRegistrationModeSelector().getSelectedItem()).isEqualTo(RegistrationMode.AUTO);
        assertThat(panel.getOauthClientIdField().isEnabled()).isTrue();
        assertThat(panel.getClientMetadataUrlField().isEnabled()).isTrue();

        panel.getRegistrationModeSelector().setSelectedItem(RegistrationMode.DCR);
        assertThat(panel.getOauthClientIdField().isEnabled()).isFalse();
        assertThat(panel.getClientMetadataUrlField().isEnabled()).isFalse();
        assertThat(panel.buildOauthHintsSnapshot().registrationMode()).isEqualTo(RegistrationMode.DCR);

        panel.getRegistrationModeSelector().setSelectedItem(RegistrationMode.CIMD);
        panel.getClientMetadataUrlField().setText("https://client.example/metadata.json");
        panel.getRedirectPortSpinner().setValue(8765);
        assertThat(panel.getOauthClientIdField().isEnabled()).isFalse();
        assertThat(panel.getClientMetadataUrlField().isEnabled()).isTrue();
        OAuthClientHints hints = panel.buildOauthHintsSnapshot();
        assertThat(hints.registrationMode()).isEqualTo(RegistrationMode.CIMD);
        assertThat(hints.clientMetadataUrl()).isEqualTo(URI.create("https://client.example/metadata.json"));
        assertThat(hints.clientId()).isNull();
    }

    @Test
    void cimdRequiresFixedRedirectPort() {
        panel.getRegistrationModeSelector().setSelectedItem(RegistrationMode.CIMD);
        panel.getClientMetadataUrlField().setText("https://client.example/metadata.json");
        panel.getRedirectPortSpinner().setValue(0);

        assertThatThrownBy(panel::buildOauthHintsSnapshot)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("fixed redirect port")
                .hasMessageContaining("CIMD");
    }

    @Test
    void automaticRegistrationRequiresFixedRedirectPortWhenCimdUrlIsSupplied() {
        panel.getRegistrationModeSelector().setSelectedItem(RegistrationMode.AUTO);
        panel.getClientMetadataUrlField().setText("https://client.example/metadata.json");
        panel.getRedirectPortSpinner().setValue(0);

        assertThatThrownBy(panel::buildOauthHintsSnapshot)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("fixed redirect port")
                .hasMessageContaining("CIMD");
    }

    @Test
    void automaticRegistrationAllowsEphemeralPortWhenBoundPreRegisteredClientWins() {
        panel.getOauthIssuerField().setText("https://issuer.example");
        panel.getOauthClientIdField().setText("registered-client");
        panel.getClientMetadataUrlField().setText("https://client.example/metadata.json");
        panel.getRedirectPortSpinner().setValue(0);

        OAuthClientHints hints = panel.buildOauthHintsSnapshot();

        assertThat(hints.clientId()).isEqualTo("registered-client");
        assertThat(hints.redirectPort()).isZero();
    }

    @Test
    void automaticRegistrationAllowsEphemeralRedirectPortWithoutCimdUrl() {
        panel.getRegistrationModeSelector().setSelectedItem(RegistrationMode.AUTO);
        panel.getClientMetadataUrlField().setText("");
        panel.getRedirectPortSpinner().setValue(0);

        assertThat(panel.buildOauthHintsSnapshot().redirectPort()).isZero();
    }

    @Test
    void buildOauthHintsAllowsEmptyIssuer() {
        panel.getOauthIssuerField().setText("");

        OAuthClientHints hints = panel.buildOauthHintsSnapshot();

        assertThat(hints.issuer()).isNull();
    }

    @Test
    void buildOauthHintsRequiresClientIdForPreRegistration() {
        panel.getOauthIssuerField().setText("");
        panel.getRegistrationModeSelector().setSelectedItem(RegistrationMode.PRE_REGISTERED);
        panel.getOauthClientIdField().setText("");

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
