package com.mcpscanner.config;

import com.mcpscanner.ExtensionMetadata;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientIdentityTest {

    private static ClientIdentity with(Map<ClientIdentityField, String> overrides) {
        return ClientIdentity.from(field -> overrides.get(field));
    }

    @Test
    void defaultsReproduceTheHardcodedHandshakeIdentity() {
        String info = ClientIdentity.defaults().profile().info().json();

        assertThat(info).isEqualTo("{\"name\":\"" + ExtensionMetadata.SCANNER_CLIENT_NAME
                + "\",\"version\":\"" + ExtensionMetadata.VERSION + "\"}");
        assertThat(ClientIdentity.defaults().profile().capabilitiesJson()).isEqualTo("{}");
        assertThat(ClientIdentity.defaults().value(ClientIdentityField.OAUTH_CLIENT_NAME))
                .isEqualTo(ExtensionMetadata.NAME);
    }

    @Test
    void theDefaultSoftwareIdIsTheExtensionsStableSoftwareId() {
        assertThat(ClientIdentity.defaults().value(ClientIdentityField.SOFTWARE_ID))
                .isEqualTo(ExtensionMetadata.SOFTWARE_ID)
                .isEqualTo("8d0f3c5e-2a71-4b9e-a6d4-5f1c9e7b3a20");
    }

    @Test
    void anEnteredSoftwareIdIsKept() {
        ClientIdentity identity = with(Map.of(ClientIdentityField.SOFTWARE_ID, "acme-id"));

        assertThat(identity.value(ClientIdentityField.SOFTWARE_ID)).isEqualTo("acme-id");
    }

    @Test
    void configuredFieldsReachTheClientInfo() {
        ClientIdentity identity = with(Map.of(
                ClientIdentityField.NAME, "acme-scanner",
                ClientIdentityField.TITLE, "Acme",
                ClientIdentityField.WEBSITE_URL, "https://acme.example",
                ClientIdentityField.ICON_URL, "https://acme.example/i.png"));

        assertThat(identity.profile().info().json()).isEqualTo(
                "{\"name\":\"acme-scanner\",\"version\":\"" + ExtensionMetadata.VERSION + "\",\"title\":\"Acme\","
                        + "\"websiteUrl\":\"https://acme.example\","
                        + "\"icons\":[{\"src\":\"https://acme.example/i.png\"}]}");
    }

    @Test
    void blankRequiredFieldsFallBackToDefaults() {
        ClientIdentity identity = with(Map.of(ClientIdentityField.NAME, "  "));

        assertThat(identity.value(ClientIdentityField.NAME)).isEqualTo(ExtensionMetadata.SCANNER_CLIENT_NAME);
    }

    @Test
    void rejectsNonHttpUrls() {
        assertThatThrownBy(() -> with(Map.of(ClientIdentityField.WEBSITE_URL, "javascript:alert(1)")))
                .hasMessageContaining("Website URL");
        assertThatThrownBy(() -> with(Map.of(ClientIdentityField.LOGO_URI, "ftp://x/y")))
                .hasMessageContaining("Logo URL");
    }

    @Test
    void iconAcceptsDataUri() {
        ClientIdentity identity = with(Map.of(ClientIdentityField.ICON_URL, "data:image/png;base64,AAAA"));

        assertThat(identity.profile().info().icons()).hasSize(1);
    }

    @Test
    void contactsAreSplitOnCommas() {
        ClientIdentity identity = with(Map.of(ClientIdentityField.CONTACT, "a@x.example, b@x.example"));

        assertThat(identity.contacts()).containsExactly("a@x.example", "b@x.example");
    }
}
