package com.mcpscanner.checks.shared.oauth;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Map;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizationParametersTest {

    private static final AuthorizationServer SERVER = new AuthorizationServer(URI.create("https://as.example"),
            URI.create("https://as.example/authorize?tenant=t1"), Optional.empty(),
            Optional.empty(), Optional.empty(), URI.create("https://mcp.example/mcp"), Optional.of("read write"),
            List.of());

    @Test
    void carriesTheS256CodeRequestParametersInOrder() {
        Map<String, String> parameters = AuthorizationParameters.of(SERVER, "code", "client-1",
                URI.create("http://127.0.0.1:49151/callback"), "s");

        assertThat(parameters).containsOnlyKeys("response_type", "client_id", "redirect_uri", "state",
                "code_challenge_method", "code_challenge", "resource", "scope");
        assertThat(parameters.keySet()).startsWith("response_type", "client_id", "redirect_uri", "state");
        assertThat(parameters).containsEntry("response_type", "code")
                .containsEntry("code_challenge_method", "S256")
                .containsEntry("resource", "https://mcp.example/mcp")
                .containsEntry("scope", "read write");
        assertThat(parameters.get("code_challenge")).matches("[A-Za-z0-9_-]{43}");
    }

    @Test
    void carriesTheChallengeOfTheGivenPkcePair() {
        Pkce pkce = Pkce.generate();

        assertThat(AuthorizationParameters.of(SERVER, "code", "c", URI.create("http://127.0.0.1/cb"), "s", pkce))
                .containsEntry("code_challenge", pkce.challenge());
    }

    @Test
    void omitsTheScopeWhenNoneWasDiscovered() {
        AuthorizationServer noScope = new AuthorizationServer(SERVER.issuer(), SERVER.authorizationEndpoint(),
                Optional.empty(), Optional.empty(), Optional.empty(), SERVER.resource(), Optional.empty(),
                List.of());

        assertThat(AuthorizationParameters.of(noScope, "code", "c", URI.create("http://127.0.0.1/cb"), "s"))
                .doesNotContainKey("scope");
    }

    @Test
    void everyRequestGetsAFreshChallenge() {
        URI callback = URI.create("http://127.0.0.1/cb");

        assertThat(AuthorizationParameters.of(SERVER, "code", "c", callback, "s").get("code_challenge"))
                .isNotEqualTo(AuthorizationParameters.of(SERVER, "code", "c", callback, "s").get("code_challenge"));
    }

    @Test
    void encodesAsFormParameters() {
        assertThat(AuthorizationParameters.encode(Map.of("state", "s\"<x> y"))).isEqualTo("state=s%22%3Cx%3E+y");
    }

    @Test
    void appendsToAnEndpointThatAlreadyHasAQuery() {
        assertThat(AuthorizationParameters.withQuery(SERVER.authorizationEndpoint(), Map.of("a", "1")))
                .isEqualTo(URI.create("https://as.example/authorize?tenant=t1&a=1"));
        assertThat(AuthorizationParameters.withQuery(URI.create("https://as.example/authorize"), Map.of("a", "1")))
                .isEqualTo(URI.create("https://as.example/authorize?a=1"));
    }
}
