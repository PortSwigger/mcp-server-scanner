package com.mcpscanner.auth.oauth;

import com.mcpscanner.ExtensionMetadata;
import com.mcpscanner.config.ClientIdentity;
import com.mcpscanner.config.ClientIdentityField;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import net.minidev.json.JSONObject;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ClientIdentityRegistrationTest {

    private static JSONObject registrationBody(ClientIdentity identity) {
        ClientMetadata metadata = new ClientMetadata();
        ClientIdentityRegistration.applyTo(metadata, identity);
        return metadata.toJSONObject();
    }

    @Test
    void defaultsRegisterTheOriginalClientNameAndTheExtensionsSoftwareId() {
        assertThat(registrationBody(ClientIdentity.defaults())).containsOnlyKeys("client_name", "software_id")
                .containsEntry("client_name", "MCP Server Scanner")
                .containsEntry("software_id", ExtensionMetadata.SOFTWARE_ID);
    }

    @Test
    void configuredFieldsAppearInTheRegistrationBody() {
        Map<ClientIdentityField, String> values = Map.of(
                ClientIdentityField.OAUTH_CLIENT_NAME, "Acme",
                ClientIdentityField.CLIENT_URI, "https://acme.example",
                ClientIdentityField.LOGO_URI, "https://acme.example/logo.png",
                ClientIdentityField.TOS_URI, "https://acme.example/tos",
                ClientIdentityField.POLICY_URI, "https://acme.example/policy",
                ClientIdentityField.CONTACT, "sec@acme.example",
                ClientIdentityField.SOFTWARE_ID, "acme-id",
                ClientIdentityField.SOFTWARE_VERSION, "9.9");

        JSONObject body = registrationBody(ClientIdentity.from(values::get));

        assertThat(body).containsEntry("client_name", "Acme")
                .containsEntry("client_uri", "https://acme.example")
                .containsEntry("logo_uri", "https://acme.example/logo.png")
                .containsEntry("tos_uri", "https://acme.example/tos")
                .containsEntry("policy_uri", "https://acme.example/policy")
                .containsEntry("software_id", "acme-id")
                .containsEntry("software_version", "9.9")
                .containsKey("contacts");
    }
}
