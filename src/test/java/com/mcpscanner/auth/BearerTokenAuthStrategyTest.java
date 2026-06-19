package com.mcpscanner.auth;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class BearerTokenAuthStrategyTest {

    @Test
    void headersReturnsAuthorizationEntry() {
        BearerTokenAuthStrategy strategy = new BearerTokenAuthStrategy("secret-token");

        assertThat(strategy.headers())
                .containsExactlyEntriesOf(Map.of("Authorization", "Bearer secret-token"));
    }

    @Test
    void rejectsTokenContainingCarriageReturn() {
        assertThatThrownBy(() -> new BearerTokenAuthStrategy("good\rsmuggled: header"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsTokenContainingLineFeed() {
        assertThatThrownBy(() -> new BearerTokenAuthStrategy("good\nX-Injected: evil"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsTokenContainingNul() {
        assertThatThrownBy(() -> new BearerTokenAuthStrategy("good\0bad"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void acceptsNormalToken() {
        BearerTokenAuthStrategy strategy = new BearerTokenAuthStrategy("eyJhbGciOiJ.payload.sig");

        assertThat(strategy.headers())
                .containsEntry("Authorization", "Bearer eyJhbGciOiJ.payload.sig");
    }

    @Test
    void headersWithEmptyTokenReturnsBearerPrefix() {
        BearerTokenAuthStrategy strategy = new BearerTokenAuthStrategy("");

        assertThat(strategy.headers())
                .containsEntry("Authorization", "Bearer ");
    }

    @Test
    void contributedHeaderNamesReturnsAuthorization() {
        BearerTokenAuthStrategy strategy = new BearerTokenAuthStrategy("token");

        assertThat(strategy.contributedHeaderNames()).containsExactly("Authorization");
    }

    @Test
    void contributedHeaderNamesIsCaseInsensitive() {
        BearerTokenAuthStrategy strategy = new BearerTokenAuthStrategy("token");

        assertThat(strategy.contributedHeaderNames()).contains("authorization", "AUTHORIZATION");
    }

    @Test
    void refreshIsNoOpAndReportsNothingHappened() {
        BearerTokenAuthStrategy strategy = new BearerTokenAuthStrategy("token");

        assertThat(strategy.refresh()).isFalse();
    }

    @Test
    void doesNotSupportRefresh() {
        BearerTokenAuthStrategy strategy = new BearerTokenAuthStrategy("token");

        assertThat(strategy.supportsRefresh()).isFalse();
    }
}
