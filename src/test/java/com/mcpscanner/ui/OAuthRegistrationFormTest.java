package com.mcpscanner.ui;

import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.core.oauth.RegistrationMode;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OAuthRegistrationFormTest {

    private static final String ISSUER = "https://issuer.example";

    @Test
    void emptyIssuerIsAllowedAndScopesPassThrough() {
        OAuthClientHints hints = form(RegistrationMode.DCR, "", "", "", null, "", 0).hints();

        assertThat(hints.issuer()).isNull();
        assertThat(hints.scopes()).containsExactly("read");
        assertThat(hints.allowDcr()).isTrue();
    }

    @Test
    void preRegistrationRequiresAClientId() {
        assertThatThrownBy(() -> form(RegistrationMode.PRE_REGISTERED, ISSUER, " ", "", ISSUER, "", 0).hints())
                .hasMessage("Client ID is required for pre-registration");
    }

    @Test
    void cimdRequiresAMetadataUrlAndAFixedPort() {
        assertThatThrownBy(() -> form(RegistrationMode.CIMD, ISSUER, "", "", null, " ", 4000).hints())
                .hasMessage("Metadata URL is required for CIMD");
        assertThatThrownBy(() -> form(RegistrationMode.CIMD, ISSUER, "", "", null, "https://c.example/m", 0).hints())
                .hasMessageStartingWith("CIMD requires a fixed redirect port");
    }

    @Test
    void automaticRegistrationNeedsAFixedPortOnlyWhenCimdWouldBeUsed() {
        assertThatThrownBy(() -> form(RegistrationMode.AUTO, ISSUER, "", "", null, "https://c.example/m", 0).hints())
                .hasMessageStartingWith("CIMD requires a fixed redirect port");
        assertThat(form(RegistrationMode.AUTO, ISSUER, "bound", "", ISSUER, "https://c.example/m", 0).hints().clientId())
                .isEqualTo("bound");
        assertThat(form(RegistrationMode.AUTO, ISSUER, "", "", null, "", 0).hints().clientMetadataUrl()).isNull();
    }

    @Test
    void aClientIdBoundToAnotherIssuerIsRejected() {
        assertThatThrownBy(() -> form(RegistrationMode.PRE_REGISTERED, ISSUER, "client", "", "https://old.example", "", 0).hints())
                .hasMessage("Client ID belongs to another or unknown issuer; re-enter it for this issuer");
    }

    @Test
    void automaticRegistrationIgnoresAClientIdNeverBoundToAnIssuer() {
        OAuthRegistrationForm unbound = form(RegistrationMode.AUTO, ISSUER, "client", "secret", null, "", 0);

        assertThat(unbound.clientIdIgnored()).isTrue();
        assertThat(unbound.hints().clientId()).isNull();
        assertThat(unbound.hints().clientSecret()).isNull();
    }

    @Test
    void boundClientKeepsATrimmedSecretAndDropsABlankOne() {
        assertThat(form(RegistrationMode.PRE_REGISTERED, ISSUER, " client ", " s3 ", ISSUER, "", 0).hints().clientSecret())
                .isEqualTo("s3");
        assertThat(form(RegistrationMode.PRE_REGISTERED, ISSUER, "client", "  ", ISSUER, "", 0).hints().clientSecret())
                .isNull();
    }

    @Test
    void dcrIgnoresClientFieldsAndMetadataUrl() {
        OAuthClientHints hints = form(RegistrationMode.DCR, ISSUER, "client", "secret", "https://old.example",
                "https://c.example/m", 0).hints();

        assertThat(hints.clientId()).isNull();
        assertThat(hints.clientMetadataUrl()).isNull();
    }

    @Test
    void cimdCarriesTheMetadataUrl() {
        OAuthClientHints hints = form(RegistrationMode.CIMD, ISSUER, "", "", null, " https://c.example/m ", 4000).hints();

        assertThat(hints.clientMetadataUrl()).isEqualTo(URI.create("https://c.example/m"));
        assertThat(hints.allowDcr()).isFalse();
        assertThat(hints.redirectPort()).isEqualTo(4000);
    }

    @Test
    void modesDeclareWhichInputsTheyUse() {
        assertThat(OAuthRegistrationForm.usesClient(RegistrationMode.AUTO)).isTrue();
        assertThat(OAuthRegistrationForm.usesClient(RegistrationMode.PRE_REGISTERED)).isTrue();
        assertThat(OAuthRegistrationForm.usesClient(RegistrationMode.DCR)).isFalse();
        assertThat(OAuthRegistrationForm.usesMetadataDocument(RegistrationMode.CIMD)).isTrue();
        assertThat(OAuthRegistrationForm.usesMetadataDocument(RegistrationMode.AUTO)).isTrue();
        assertThat(OAuthRegistrationForm.usesMetadataDocument(RegistrationMode.PRE_REGISTERED)).isFalse();
    }

    private static OAuthRegistrationForm form(RegistrationMode mode, String issuer, String clientId, String secret,
                                              String clientIssuer, String metadataUrl, int port) {
        return new OAuthRegistrationForm(issuer, List.of("read"), com.mcpscanner.auth.oauth.ScopeSelection.none(), mode, clientId, secret,
                clientIssuer, metadataUrl, port);
    }
}
