package com.mcpscanner.checks.shared.oauth;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ClientCredentialsTest {

    private static final Map<String, String> GRANT = Map.of("grant_type", "authorization_code");

    @Test
    void aPublicClientSendsItsClientIdInTheFormAndNoAuthorizationHeader() {
        ClientCredentials credentials = ClientCredentials.publicClient("c1");

        assertThat(credentials.form(GRANT)).containsEntry("client_id", "c1").doesNotContainKey("client_secret");
        assertThat(credentials.headers()).isEmpty();
    }

    @Test
    void aSecretForTheFormIsSentAlongsideTheClientId() {
        ClientCredentials credentials = new ClientCredentials("c1",
                Optional.of(new ClientSecret("s1", ClientSecretMethod.POST)));

        assertThat(credentials.form(GRANT)).containsEntry("grant_type", "authorization_code")
                .containsEntry("client_id", "c1").containsEntry("client_secret", "s1");
        assertThat(credentials.headers()).isEmpty();
    }

    @Test
    void aBasicSecretIsSentOnlyInTheAuthorizationHeaderFormEncodedFirst() {
        ClientCredentials credentials = new ClientCredentials("c 1",
                Optional.of(new ClientSecret("s:1", ClientSecretMethod.BASIC)));

        assertThat(credentials.form(GRANT)).containsOnlyKeys("grant_type");
        assertThat(credentials.headers()).containsExactly(Map.entry("Authorization", "Basic "
                + Base64.getEncoder().encodeToString("c+1:s%3A1".getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    void keepsTheGrantParametersInOrderBeforeTheClientId() {
        ClientCredentials credentials = ClientCredentials.publicClient("c1");
        Map<String, String> ordered = new java.util.LinkedHashMap<>();
        ordered.put("token", "t");
        ordered.put("token_type_hint", "access_token");

        assertThat(credentials.form(ordered).keySet()).containsExactly("token", "token_type_hint", "client_id");
    }

    @Test
    void neverPrintsTheSecret() {
        assertThat(new ClientCredentials("c1", Optional.of(new ClientSecret("s3cr3t", ClientSecretMethod.POST))))
                .asString().doesNotContain("s3cr3t");
    }
}
