package com.mcpscanner.config;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import com.mcpscanner.core.oauth.RegistrationMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ExtensionConfigStoreTest {

    private static final Locale TURKISH = Locale.forLanguageTag("tr-TR");

    private PersistedObject store;
    private Logging logging;
    private ExtensionConfigStore config;

    @BeforeEach
    void setUp() {
        store = mock(PersistedObject.class);
        logging = mock(Logging.class);
        config = new ExtensionConfigStore(store, logging);
    }

    @Test
    void migratesLegacyRegistrationChoiceWithoutDiscardingIssuerOrClientId() {
        when(store.getBoolean("mcp.oauth.skip_dcr")).thenReturn(true);
        when(store.getString("mcp.oauth.issuer")).thenReturn("https://issuer.example");
        when(store.getString("mcp.oauth.client_id")).thenReturn("existing-client");
        config = new ExtensionConfigStore(store, logging);

        assertThat(config.oauthRegistrationMode()).isEqualTo(RegistrationMode.PRE_REGISTERED);
        assertThat(config.oauthIssuer()).isEqualTo("https://issuer.example");
        assertThat(config.oauthClientId()).isEqualTo("existing-client");
        verify(store).setString("mcp.oauth.registration_mode", "PRE_REGISTERED");
        verify(store).setString("mcp.oauth.client_issuer", "https://issuer.example");
    }

    @Test
    void unknownSavedRegistrationModeFallsBackToAutoWithoutActivatingOldClient() {
        when(store.getString("mcp.oauth.registration_mode")).thenReturn("FUTURE_MODE");
        when(store.getBoolean("mcp.oauth.skip_dcr")).thenReturn(true);
        config = new ExtensionConfigStore(store, logging);

        assertThat(config.oauthRegistrationMode()).isEqualTo(RegistrationMode.AUTO);
        verify(store).setString("mcp.oauth.registration_mode", "AUTO");
    }

    @Test
    void readingTheRegistrationModeNeverWritesTheStore() {
        when(store.getBoolean("mcp.oauth.skip_dcr")).thenReturn(true);
        when(store.getString("mcp.oauth.issuer")).thenReturn("https://issuer.example");
        config = new ExtensionConfigStore(store, logging);
        clearInvocations(store);

        assertThat(config.oauthRegistrationMode()).isEqualTo(RegistrationMode.PRE_REGISTERED);

        verify(store, never()).setString(anyString(), anyString());
    }

    @Test
    void constructingOverAFreshStoreWritesNothing() {
        verify(store, never()).setString(anyString(), anyString());
    }

    @Test
    void hashedEndpointKeysDoNotDependOnTheDefaultLocale() {
        String englishKey = withDefaultLocale(Locale.ENGLISH, () -> dontAskAgainKeyWrittenFor("https://WIKI.example/mcp"));
        String turkishKey = withDefaultLocale(TURKISH, () -> dontAskAgainKeyWrittenFor("https://WIKI.example/mcp"));

        assertThat(turkishKey).isEqualTo(englishKey);
    }

    @Test
    void hashedIssuerKeysDoNotDependOnTheDefaultLocale() {
        String englishKey = withDefaultLocale(Locale.ENGLISH, () -> dcrClientUriKeyWrittenFor("https://LOGIN.example"));
        String turkishKey = withDefaultLocale(TURKISH, () -> dcrClientUriKeyWrittenFor("https://LOGIN.example"));

        assertThat(turkishKey).isEqualTo(englishKey);
    }

    @Test
    void endpointKeysPersistedUnderTurkishLowercasingStillLoad() {
        String legacyHash = sha256Prefix("https://w\u0131k\u0131.example/mcp");
        when(store.getBoolean(anyString())).thenReturn(null);
        when(store.getBoolean("mcp.scope." + legacyHash + ".dontAskAgain")).thenReturn(true);
        when(store.getBoolean("mcp.scope." + legacyHash + ".tool.ping.selected")).thenReturn(false);

        withDefaultLocale(TURKISH, () -> {
            assertThat(config.dontAskAgain("https://WIKI.example/mcp")).isTrue();
            assertThat(config.toolSelected("https://WIKI.example/mcp", "ping")).isFalse();
            return null;
        });
    }

    @Test
    void issuerKeysPersistedUnderTurkishLowercasingStillLoad() {
        String legacyHash = sha256Prefix("https://log\u0131n.example");
        when(store.getString("mcp.dcr." + legacyHash + ".reg_uri")).thenReturn("https://login.example/reg/1");

        withDefaultLocale(TURKISH, () -> {
            assertThat(config.dcrRegistrationClientUri("https://LOGIN.example"))
                    .isEqualTo("https://login.example/reg/1");
            return null;
        });
    }

    private String dontAskAgainKeyWrittenFor(String endpoint) {
        clearInvocations(store);
        config.setDontAskAgain(endpoint, true);
        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        verify(store).setBoolean(key.capture(), eq(true));
        return key.getValue();
    }

    private String dcrClientUriKeyWrittenFor(String issuer) {
        clearInvocations(store);
        config.setDcrRegistrationClientUri(issuer, "https://login.example/reg/1");
        ArgumentCaptor<String> key = ArgumentCaptor.forClass(String.class);
        verify(store).setString(key.capture(), eq("https://login.example/reg/1"));
        return key.getValue();
    }

    private static <T> T withDefaultLocale(Locale locale, Supplier<T> action) {
        Locale previous = Locale.getDefault();
        Locale.setDefault(locale);
        try {
            return action.get();
        } finally {
            Locale.setDefault(previous);
        }
    }

    private static String sha256Prefix(String value) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void readsEndpointFromPersistedString() {
        when(store.getString("mcp.endpoint")).thenReturn("https://example.com/mcp");

        assertThat(config.endpoint()).isEqualTo("https://example.com/mcp");
    }

    @Test
    void writesEndpointAsString() {
        config.setEndpoint("https://example.com/mcp");

        verify(store).setString("mcp.endpoint", "https://example.com/mcp");
    }

    @Test
    void endpointListenersHearOnlyActualChanges() {
        Runnable listener = mock(Runnable.class);
        config.addEndpointChangeListener(listener);
        when(store.getString("mcp.endpoint")).thenReturn("https://a.example/mcp");

        config.setEndpoint("https://a.example/mcp");
        verify(listener, never()).run();

        config.setEndpoint("https://b.example/mcp");
        verify(listener).run();
    }

    @Test
    void sendToAuthenticationHandlingDefaultsOffAndPersistsSelection() {
        Runnable listener = mock(Runnable.class);
        config.addSettingsChangeListener(listener);

        assertThat(config.handleSendToAuthentication()).isFalse();

        config.setHandleSendToAuthentication(true);
        verify(store).setBoolean("mcp.sendto.handle_auth", true);
        verify(listener).run();
        when(store.getBoolean("mcp.sendto.handle_auth")).thenReturn(true);

        assertThat(config.handleSendToAuthentication()).isTrue();
    }

    @Test
    void serverPingAnswersDefaultOnAndPersistSelection() {
        Runnable listener = mock(Runnable.class);
        config.addSettingsChangeListener(listener);
        when(store.getBoolean("mcp.server_pings.answer")).thenReturn(null);

        assertThat(config.answerServerPings()).isTrue();

        config.setAnswerServerPings(false);
        verify(store).setBoolean("mcp.server_pings.answer", false);
        verify(listener).run();
        when(store.getBoolean("mcp.server_pings.answer")).thenReturn(false);

        assertThat(config.answerServerPings()).isFalse();
    }

    @Test
    void burpNetworkingDefaultsOnAndPersistsSelection() {
        Runnable listener = mock(Runnable.class);
        config.addSettingsChangeListener(listener);
        when(store.getBoolean("mcp.networking.use_burp")).thenReturn(null);

        assertThat(config.useBurpNetworking()).isTrue();

        config.setUseBurpNetworking(false);
        verify(store).setBoolean("mcp.networking.use_burp", false);
        verify(listener).run();
        when(store.getBoolean("mcp.networking.use_burp")).thenReturn(false);

        assertThat(config.useBurpNetworking()).isFalse();
    }

    @Test
    void theLegacyAutoDetectCheckboxReadsOnUnlessItWasTurnedOff() {
        when(store.getBoolean("mcp.auth.auto_detect")).thenReturn(null);
        assertThat(config.legacyAutoDetectAuth()).isTrue();

        when(store.getBoolean("mcp.auth.auto_detect")).thenReturn(false);
        assertThat(config.legacyAutoDetectAuth()).isFalse();
    }

    @Test
    void theAutoDetectMigrationIsRecordedOnce() {
        assertThat(config.autoDetectMigrated()).isFalse();

        config.markAutoDetectMigrated();

        verify(store).setBoolean("mcp.auth.auto_detect.migrated", true);
    }

    @Test
    void redirectModeDefaultsOffAndPersistsSelection() {
        assertThat(config.redirectMode()).isEqualTo(RedirectMode.METHOD_PRESERVING_SAME_ORIGIN);

        config.setRedirectMode(RedirectMode.ALWAYS);
        verify(store).setString("mcp.redirect.mode", "ALWAYS");
        when(store.getString("mcp.redirect.mode")).thenReturn("ALWAYS");

        assertThat(config.redirectMode()).isEqualTo(RedirectMode.ALWAYS);
    }

    @Test
    void scanModeIsUnsetUntilChosenAndPersistsTheChoice() {
        assertThat(config.scanMode()).isNull();

        config.setScanMode("MCP_AND_BURP");
        verify(store).setString("mcp.scan.mode", "MCP_AND_BURP");
        when(store.getString("mcp.scan.mode")).thenReturn("MCP_AND_BURP");

        assertThat(config.scanMode()).isEqualTo("MCP_AND_BURP");
    }

    @Test
    void resourceCapsDefaultGenerouslyWhenUnset() {
        assertThat(config.resourceCap(ResourceCap.PROXY_POST_BODY_BYTES)).isEqualTo(32L * 1024 * 1024);
        assertThat(config.resourceCap(ResourceCap.SSE_PENDING_RESPONSE_BYTES)).isEqualTo(64L * 1024 * 1024);
        assertThat(config.resourceCap(ResourceCap.DISCOVERY_TOTAL_BYTES)).isEqualTo(256L * 1024 * 1024);
        assertThat(config.resourceCap(ResourceCap.DISCOVERY_MAX_PAGES)).isEqualTo(100L);
    }

    @Test
    void extensionScanWorkersDefaultToBurpScannersTenAndAcceptOneToFifty() {
        assertThat(config.extensionScanWorkers()).isEqualTo(10);
        assertThat(ResourceCap.EXTENSION_SCAN_WORKERS.kind()).isEqualTo(CapKind.SCAN_THROUGHPUT);
        assertThat(ResourceCap.ofKind(CapKind.SAFETY_LIMIT)).doesNotContain(ResourceCap.EXTENSION_SCAN_WORKERS)
                .contains(ResourceCap.PROXY_POST_BODY_BYTES, ResourceCap.SSE_PENDING_RESPONSE_BYTES,
                        ResourceCap.DISCOVERY_TOTAL_BYTES, ResourceCap.DISCOVERY_MAX_PAGES);

        config.setResourceCap(ResourceCap.EXTENSION_SCAN_WORKERS, 1L);
        config.setResourceCap(ResourceCap.EXTENSION_SCAN_WORKERS, 50L);
        verify(store).setLong("mcp.scan.engine_workers", 50L);
        when(store.getLong("mcp.scan.engine_workers")).thenReturn(50L);
        assertThat(config.extensionScanWorkers()).isEqualTo(50);
        assertThatThrownBy(() -> config.setResourceCap(ResourceCap.EXTENSION_SCAN_WORKERS, 51L))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void collectIdsRequestsPerUserHasNoLimitByDefaultAndAcceptsZeroToClearIt() {
        assertThat(ResourceCap.MINING_REQUESTS_PER_USER.key()).isEqualTo("mcp.mining.requests_per_user");
        assertThat(ResourceCap.MINING_REQUESTS_PER_USER.label()).isEqualTo("Collect IDs requests per user");
        assertThat(config.resourceCap(ResourceCap.MINING_REQUESTS_PER_USER)).isZero();

        config.setResourceCap(ResourceCap.MINING_REQUESTS_PER_USER, 0L);
        config.setResourceCap(ResourceCap.MINING_REQUESTS_PER_USER, 5000L);

        verify(store).setLong("mcp.mining.requests_per_user", 5000L);
        assertThatThrownBy(() -> config.setResourceCap(ResourceCap.MINING_REQUESTS_PER_USER, -1L))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("between 0 and");
        assertThatThrownBy(() -> config.setResourceCap(ResourceCap.DISCOVERY_MAX_PAGES, 0L))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("between 1 and");
    }

    @Test
    void previouslyPersistedPostBodyLimitStillLoads() {
        when(store.getLong("mcp.proxy.post_body_limit_bytes")).thenReturn(1_048_577L);

        assertThat(config.resourceCap(ResourceCap.PROXY_POST_BODY_BYTES)).isEqualTo(1_048_577L);
    }

    @Test
    void persistsResourceCapAndBlankRestoresDefault() {
        config.setResourceCap(ResourceCap.DISCOVERY_MAX_PAGES, 250L);
        verify(store).setLong("mcp.cap.discovery_max_pages", 250L);
        when(store.getLong("mcp.cap.discovery_max_pages")).thenReturn(250L);
        assertThat(config.resourceCap(ResourceCap.DISCOVERY_MAX_PAGES)).isEqualTo(250L);

        config.setResourceCap(ResourceCap.DISCOVERY_MAX_PAGES, null);
        verify(store).deleteLong("mcp.cap.discovery_max_pages");
    }

    @Test
    void rejectsUndersizedAndOversizedResourceCaps() {
        for (ResourceCap cap : ResourceCap.values()) {
            assertThatThrownBy(() -> config.setResourceCap(cap, cap.minValue() - 1))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> config.setResourceCap(cap, -5L)).isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> config.setResourceCap(ResourceCap.PROXY_POST_BODY_BYTES, (long) Integer.MAX_VALUE))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void ignoresInvalidPersistedResourceCap() {
        when(store.getLong("mcp.cap.discovery_max_pages")).thenReturn(0L);

        assertThat(config.resourceCap(ResourceCap.DISCOVERY_MAX_PAGES)).isEqualTo(100L);
    }

    @Test
    void roundTripsScopeListAsJson() {
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
        config.setScopes(List.of(
                new ExtensionConfigStore.PersistedScope("read", true, "discovered"),
                new ExtensionConfigStore.PersistedScope("write", false, "custom")));
        verify(store).setString(eq("mcp.oauth.scopes"), captor.capture());

        when(store.getString("mcp.oauth.scopes")).thenReturn(captor.getValue());
        List<ExtensionConfigStore.PersistedScope> read = config.scopes();

        assertThat(read).hasSize(2);
        assertThat(read.get(0).name()).isEqualTo("read");
        assertThat(read.get(0).enabled()).isTrue();
        assertThat(read.get(0).source()).isEqualTo("discovered");
        assertThat(read.get(1).source()).isEqualTo("custom");
    }

    @Test
    void returnsEmptyScopesWhenUnset() {
        when(store.getString("mcp.oauth.scopes")).thenReturn(null);

        assertThat(config.scopes()).isEmpty();
    }

    @Test
    void logsCorruptScopeJsonAndReturnsEmpty() {
        when(store.getString("mcp.oauth.scopes")).thenReturn("not-valid-json{");

        List<ExtensionConfigStore.PersistedScope> read = config.scopes();

        assertThat(read).isEmpty();
        verify(logging).logToError(contains("Corrupt"));
    }

    @Test
    void doesNotPersistBearerOrClientSecrets() {
        long nonDcrSecretMethods = java.util.Arrays.stream(ExtensionConfigStore.class.getDeclaredMethods())
                .map(java.lang.reflect.Method::getName)
                .filter(name -> {
                    String lower = name.toLowerCase();
                    boolean isSensitive = lower.contains("token") || lower.contains("secret");
                    boolean isDcrManagement = lower.contains("dcr");
                    return isSensitive && !isDcrManagement;
                })
                .count();
        assertThat(nonDcrSecretMethods).isZero();
    }

    @Test
    void dcrRegistrationManagementTokenIsKeptInMemoryPerIssuerAndNeverPersisted() {
        config.setDcrRegistrationManagementToken("https://as.example.com/", "tok-abc");

        verify(store, never()).setString(anyString(), anyString());
        assertThat(config.dcrRegistrationManagementToken("https://AS.example.com")).isEqualTo("tok-abc");
        assertThat(config.dcrRegistrationManagementToken("https://other.example.com")).isNull();
    }

    @Test
    void managementTokensSavedByOlderVersionsAreDeletedOnLoadAndNotRead() {
        String issuer = "https://as.example.com";
        String legacyTokenKey = HashedKey.of("mcp.dcr.", issuer, ".reg_token").canonical();
        String clientUriKey = HashedKey.of("mcp.dcr.", issuer, ".reg_uri").canonical();
        when(store.stringKeys()).thenReturn(Set.of(legacyTokenKey, clientUriKey, "mcp.endpoint"));
        when(store.getString(anyString())).thenReturn("saved-token");

        config = new ExtensionConfigStore(store, logging);

        verify(store).deleteString(legacyTokenKey);
        verify(store, never()).deleteString(clientUriKey);
        verify(store, never()).deleteString("mcp.endpoint");
        assertThat(config.dcrRegistrationManagementToken(issuer)).isNull();
    }

    @Test
    void dcrRegistrationClientUriRoundTripsPerIssuer() {
        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);

        config.setDcrRegistrationClientUri("https://as.example.com", "https://as.example.com/register/client-1");
        verify(store).setString(keyCaptor.capture(),
                org.mockito.ArgumentMatchers.eq("https://as.example.com/register/client-1"));

        String writtenKey = keyCaptor.getValue();
        assertThat(writtenKey).startsWith("mcp.dcr.");
        assertThat(writtenKey).endsWith(".reg_uri");

        when(store.getString(writtenKey)).thenReturn("https://as.example.com/register/client-1");
        assertThat(config.dcrRegistrationClientUri("https://as.example.com"))
                .isEqualTo("https://as.example.com/register/client-1");
    }

    @Test
    void dcrFieldsAreIsolatedBetweenIssuers() {
        ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);

        config.setDcrRegistrationManagementToken("https://issuer-a.example.com", "tok-a");
        config.setDcrRegistrationManagementToken("https://issuer-b.example.com", "tok-b");
        config.setDcrRegistrationClientUri("https://issuer-a.example.com", "https://issuer-a.example.com/reg/c1");
        config.setDcrRegistrationClientUri("https://issuer-b.example.com", "https://issuer-b.example.com/reg/c2");

        verify(store, org.mockito.Mockito.times(2)).setString(captor.capture(),
                org.mockito.ArgumentMatchers.anyString());

        List<String> keys = captor.getAllValues();
        assertThat(keys.get(0)).isNotEqualTo(keys.get(1));
        assertThat(config.dcrRegistrationManagementToken("https://issuer-a.example.com")).isEqualTo("tok-a");
        assertThat(config.dcrRegistrationManagementToken("https://issuer-b.example.com")).isEqualTo("tok-b");
    }

    @Test
    void toolSelectedRoundTripsThroughHashedKey() {
        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        config.setToolSelected("https://srv.example/mcp", "ping_host", true);
        verify(store).setBoolean(keyCaptor.capture(), eq(true));
        String writtenKey = keyCaptor.getValue();

        when(store.getBoolean(writtenKey)).thenReturn(true);

        assertThat(config.toolSelected("https://srv.example/mcp", "ping_host")).isTrue();
        assertThat(writtenKey).startsWith("mcp.scope.");
        assertThat(writtenKey).contains(".tool.ping_host.selected");
    }

    @Test
    void toolSelectedReturnsNullWhenUnset() {
        when(store.getBoolean(org.mockito.ArgumentMatchers.anyString())).thenReturn(null);

        assertThat(config.toolSelected("https://srv.example/mcp", "ping_host")).isNull();
    }

    @Test
    void dontAskAgainDefaultsFalseWhenUnset() {
        when(store.getBoolean(org.mockito.ArgumentMatchers.anyString())).thenReturn(null);

        assertThat(config.dontAskAgain("https://srv.example/mcp")).isFalse();
    }

    @Test
    void dontAskAgainRoundTrips() {
        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        config.setDontAskAgain("https://srv.example/mcp", true);
        verify(store).setBoolean(keyCaptor.capture(), eq(true));

        when(store.getBoolean(keyCaptor.getValue())).thenReturn(true);

        assertThat(config.dontAskAgain("https://srv.example/mcp")).isTrue();
        assertThat(keyCaptor.getValue()).endsWith(".dontAskAgain");
    }

    @Test
    void differentEndpointsProduceDistinctKeys() {
        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);

        config.setToolSelected("https://a.example/mcp", "ping", true);
        config.setToolSelected("https://b.example/mcp", "ping", true);

        verify(store, org.mockito.Mockito.times(2))
                .setBoolean(keyCaptor.capture(), eq(true));
        List<String> capturedKeys = keyCaptor.getAllValues();
        assertThat(capturedKeys.get(0)).isNotEqualTo(capturedKeys.get(1));
    }

    @Test
    void trailingSlashEndpointSharesKeyWithCanonicalForm() {
        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);

        config.setToolSelected("https://a.example/mcp", "ping", true);
        config.setToolSelected("https://a.example/mcp/", "ping", true);
        config.setToolSelected("https://A.Example/mcp", "ping", true);

        verify(store, org.mockito.Mockito.times(3))
                .setBoolean(keyCaptor.capture(), eq(true));
        List<String> capturedKeys = keyCaptor.getAllValues();
        assertThat(capturedKeys.get(0)).isEqualTo(capturedKeys.get(1));
        assertThat(capturedKeys.get(0)).isEqualTo(capturedKeys.get(2));
    }

    @Test
    void clientIdentityRoundTripsThroughStoredKeys() {
        when(store.getString("mcp.client.name")).thenReturn("acme");
        when(store.getString("mcp.client.title")).thenReturn("Acme Title");

        ClientIdentity identity = config.clientIdentity();

        assertThat(identity.value(ClientIdentityField.NAME)).isEqualTo("acme");
        assertThat(identity.value(ClientIdentityField.TITLE)).isEqualTo("Acme Title");
        config.saveClientIdentity(identity);
        verify(store).setString("mcp.client.name", "acme");
        verify(store).setString("mcp.client.oauth.client_name", "MCP Server Scanner");
    }

    @Test
    void invalidStoredClientIdentityFallsBackToDefaultsInTheProvider() {
        when(store.getString("mcp.client.website_url")).thenReturn("javascript:x");

        assertThat(ClientIdentityProvider.stored(config).current()).isEqualTo(ClientIdentity.defaults());
    }

    @Test
    void clearingDontAskAgainForAllServersLeavesOtherSettings() {
        ExtensionConfigStore configStore = com.mcpscanner.testutil.InMemoryPersistedObject.configStore();
        configStore.setDontAskAgain("https://one.example/mcp", true);
        configStore.setDontAskAgain("https://two.example/mcp", true);
        configStore.setToolSelected("https://one.example/mcp", "echo", true);

        assertThat(configStore.clearDontAskAgainForAllServers()).isEqualTo(2);

        assertThat(configStore.dontAskAgain("https://one.example/mcp")).isFalse();
        assertThat(configStore.dontAskAgain("https://two.example/mcp")).isFalse();
        assertThat(configStore.toolSelected("https://one.example/mcp", "echo")).isTrue();
    }
}
