package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import com.mcpscanner.checks.shared.oauth.AuthorizationServer;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizationRequestFactoryTest {

    private static final URI AUTHORIZE = URI.create("https://auth.example.com/authorize");
    private static final URI RESOURCE = URI.create("https://mcp.example.com/mcp");
    private static final URI CALLBACK = URI.create("https://client.example.com/cb?tenant=a&b=c");

    private static AuthorizationServer server(URI authorizationEndpoint, Optional<String> scope) {
        return new AuthorizationServer(URI.create("https://auth.example.com"), authorizationEndpoint,
                Optional.empty(), Optional.empty(), Optional.empty(), RESOURCE, scope, List.of());
    }

    private static URI build(AuthorizationServer server, AuthorizationVariant variant) {
        return new AuthorizationRequestFactory(server).build("client-1", CALLBACK, "state 1", variant);
    }

    private static Map<String, String> parameters(AuthorizationVariant variant) {
        return QueryParameters.of(build(server(AUTHORIZE, Optional.empty()), variant));
    }

    @Test
    void targetsTheAuthorizationEndpoint() {
        URI request = build(server(AUTHORIZE, Optional.empty()), AuthorizationVariant.STANDARD);

        assertThat(request.toString()).startsWith(AUTHORIZE + "?");
    }

    @Test
    void carriesTheStandardPkceAuthorizationParameters() {
        assertThat(parameters(AuthorizationVariant.STANDARD))
                .containsEntry("response_type", "code")
                .containsEntry("client_id", "client-1")
                .containsEntry("redirect_uri", CALLBACK.toString())
                .containsEntry("state", "state 1")
                .containsEntry("code_challenge_method", "S256")
                .containsEntry("resource", RESOURCE.toString())
                .doesNotContainKeys("scope", "response_mode", "prompt");
    }

    @Test
    void codeChallengeIsAnUnpaddedBase64UrlSha256Digest() {
        assertThat(parameters(AuthorizationVariant.STANDARD).get("code_challenge")).matches("[A-Za-z0-9_-]{43}");
    }

    @Test
    void codeChallengeIsFreshForEachRequest() {
        assertThat(parameters(AuthorizationVariant.STANDARD).get("code_challenge"))
                .isNotEqualTo(parameters(AuthorizationVariant.STANDARD).get("code_challenge"));
    }

    @Test
    void addsTheScopeWhenTheServerHasOne() {
        URI request = build(server(AUTHORIZE, Optional.of("read write")), AuthorizationVariant.STANDARD);

        assertThat(QueryParameters.of(request)).containsEntry("scope", "read write");
    }

    @Test
    void fragmentVariantRequestsFragmentResponseMode() {
        assertThat(parameters(AuthorizationVariant.FRAGMENT)).containsEntry("response_mode", "fragment")
                .containsEntry("response_type", "code");
    }

    @Test
    void silentVariantRequestsNoPrompt() {
        assertThat(parameters(AuthorizationVariant.SILENT)).containsEntry("prompt", "none");
    }

    @Test
    void unsupportedResponseTypeVariantChangesOnlyTheResponseType() {
        assertThat(parameters(AuthorizationVariant.UNSUPPORTED_RESPONSE_TYPE))
                .containsEntry("response_type", "scancheck_unsupported")
                .doesNotContainKeys("response_mode", "prompt");
    }

    @Test
    void consentDenialVariantDeclinesWithTheCommonDenialFields() {
        assertThat(parameters(AuthorizationVariant.CONSENT_DENIAL))
                .containsEntry("response_type", "code")
                .containsEntry("allow", "false")
                .containsEntry("decision", "deny");
    }

    @Test
    void formCarriesTheSameParametersAsTheQueryWithoutTheEndpoint() {
        AuthorizationRequestFactory factory = new AuthorizationRequestFactory(server(AUTHORIZE, Optional.empty()));

        Map<String, String> form = QueryParameters.ofEncoded(
                factory.form("client-1", CALLBACK, "state 1", AuthorizationVariant.CONSENT_DENIAL));

        assertThat(form).containsEntry("client_id", "client-1")
                .containsEntry("redirect_uri", CALLBACK.toString())
                .containsEntry("state", "state 1")
                .containsEntry("allow", "false")
                .doesNotContainKey("tenant");
        assertThat(factory.endpoint()).isEqualTo(AUTHORIZE);
    }

    @Test
    void appendsToAnExistingEndpointQuery() {
        URI request = build(server(URI.create("https://auth.example.com/authorize?tenant=t1"), Optional.empty()),
                AuthorizationVariant.STANDARD);

        assertThat(request.toString()).startsWith("https://auth.example.com/authorize?tenant=t1&response_type=code");
        assertThat(QueryParameters.of(request)).containsEntry("tenant", "t1").containsEntry("client_id", "client-1");
    }
}
