package com.mcpscanner.config;

import burp.api.montoya.logging.Logging;
import burp.api.montoya.persistence.PersistedObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ExtensionConfigStoreTest {

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
        // DCR management credentials (dcrRegistrationManagementToken / setDcrRegistrationManagementToken)
        // are legitimately persisted per-issuer so that operators can manage their registered client.
        // This guard ensures no other token/secret fields creep in.
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
    void dcrRegistrationManagementTokenRoundTripsPerIssuer() {
        ArgumentCaptor<String> keyCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> valueCaptor = ArgumentCaptor.forClass(String.class);

        config.setDcrRegistrationManagementToken("https://as.example.com/", "tok-abc");
        verify(store).setString(keyCaptor.capture(), valueCaptor.capture());

        String writtenKey = keyCaptor.getValue();
        assertThat(writtenKey).startsWith("mcp.dcr.");
        assertThat(writtenKey).endsWith(".reg_token");

        when(store.getString(writtenKey)).thenReturn("tok-abc");
        assertThat(config.dcrRegistrationManagementToken("https://as.example.com/")).isEqualTo("tok-abc");
        assertThat(config.dcrRegistrationManagementToken("https://as.example.com")).isEqualTo("tok-abc");
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

        verify(store, org.mockito.Mockito.times(4)).setString(captor.capture(),
                org.mockito.ArgumentMatchers.anyString());

        List<String> keys = captor.getAllValues();
        // token keys for issuer-a and issuer-b must differ
        assertThat(keys.get(0)).isNotEqualTo(keys.get(1));
        // uri keys for issuer-a and issuer-b must differ
        assertThat(keys.get(2)).isNotEqualTo(keys.get(3));
        // token key and uri key for same issuer must differ
        assertThat(keys.get(0)).isNotEqualTo(keys.get(2));
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
}
