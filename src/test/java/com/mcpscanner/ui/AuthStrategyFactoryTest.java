package com.mcpscanner.ui;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.CustomHeaderAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.oauth.OAuthTokens;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthStrategyFactoryTest {

    private final AuthStrategyFactory factory = new AuthStrategyFactory();

    @Test
    void noneAuthTypeProducesNoAuthStrategy() {
        AuthStrategy strategy = factory.create(
                ServerConfigPanel.AUTH_NONE, "ignored", Map.of("X", "y"), null);

        assertThat(strategy).isInstanceOf(NoAuthStrategy.class);
        assertThat(strategy.headers()).isEmpty();
    }

    @Test
    void unknownAuthTypeFallsBackToNoAuthStrategy() {
        AuthStrategy strategy = factory.create("Something Else", "tok", Map.of(), null);

        assertThat(strategy).isInstanceOf(NoAuthStrategy.class);
    }

    @Test
    void bearerAuthTypeCarriesTheTrimmedToken() {
        AuthStrategy strategy = factory.create(
                ServerConfigPanel.AUTH_BEARER, "  my-secret-token  ", Map.of(), null);

        assertThat(strategy).isInstanceOf(BearerTokenAuthStrategy.class);
        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer my-secret-token");
    }

    @Test
    void bearerAuthTypeAcceptsEmptyTokenWithoutThrowing() {
        AuthStrategy strategy = factory.create(ServerConfigPanel.AUTH_BEARER, "   ", Map.of(), null);

        assertThat(strategy).isInstanceOf(BearerTokenAuthStrategy.class);
        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer ");
    }

    @Test
    void customAuthTypeProducesCustomHeaderStrategyWithValidatedHeaders() {
        AuthStrategy strategy = factory.create(
                ServerConfigPanel.AUTH_CUSTOM, "ignored",
                Map.of("X-Api-Key", "abc123", "X-Custom", "value"), null);

        assertThat(strategy).isInstanceOf(CustomHeaderAuthStrategy.class);
        assertThat(strategy.headers())
                .containsEntry("X-Api-Key", "abc123")
                .containsEntry("X-Custom", "value");
    }

    @Test
    void customAuthTypeRoutesThroughHeaderValidatorRejectingReservedHeader() {
        assertThatThrownBy(() -> factory.create(
                ServerConfigPanel.AUTH_CUSTOM, "ignored",
                Map.of("Authorization", "Bearer abc"), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("reserved")
                .hasMessageContaining("Authorization");
    }

    @Test
    void customAuthTypeRoutesThroughHeaderValidatorRejectingCrlfInValue() {
        assertThatThrownBy(() -> factory.create(
                ServerConfigPanel.AUTH_CUSTOM, "ignored",
                Map.of("X-Bad", "v\r\nInjected: yes"), null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("X-Bad");
    }

    @Test
    void oauthAuthTypeReturnsThePublishedStrategy() {
        OAuthAuthCodeStrategy published = oauthStrategy();

        AuthStrategy strategy = factory.create(
                ServerConfigPanel.AUTH_OAUTH, "ignored", Map.of(), published);

        assertThat(strategy).isSameAs(published);
    }

    @Test
    void oauthAuthTypeWithoutPublishedStrategyFailsLoudInsteadOfSilentlyDegradingToNoAuth() {
        assertThatThrownBy(() -> factory.create(ServerConfigPanel.AUTH_OAUTH, "ignored", Map.of(), null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("OAuth selected but no authorization strategy has been established");
    }

    private static OAuthAuthCodeStrategy oauthStrategy() {
        return new OAuthAuthCodeStrategy(
                URI.create("https://issuer.example.com"),
                List.of(),
                "client-id",
                null,
                null,
                new OAuthTokens(new BearerAccessToken("tok"),
                        new RefreshToken("rt"),
                        Instant.now().plusSeconds(600),
                        "alice"),
                (issuer, id, secret, rt, resource) -> {
                    throw new UnsupportedOperationException("not used");
                },
                Clock.systemUTC(),
                new com.mcpscanner.logging.McpEventLog(null));
    }
}
