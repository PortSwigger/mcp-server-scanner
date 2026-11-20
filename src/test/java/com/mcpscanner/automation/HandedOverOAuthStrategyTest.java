package com.mcpscanner.automation;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.grant.ClientType;
import com.mcpscanner.auth.grant.IssuedTokens;
import com.mcpscanner.auth.grant.LiveRefreshGrant;
import com.mcpscanner.auth.grant.OAuthClient;
import com.mcpscanner.auth.grant.RefreshGrant;
import com.mcpscanner.identity.IdentityAuthKind;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class HandedOverOAuthStrategyTest {

    private static final URI ISSUER = URI.create("http://127.0.0.1:41000");
    private static final URI RESOURCE = URI.create("http://127.0.0.1:41000/mcp");
    static final CommandOAuthSession SESSION = new CommandOAuthSession("access-1", "refresh-1", ISSUER, RESOURCE,
            "client-1", "secret-1", ClientType.CONFIDENTIAL_REGISTERED, List.of("mcp:tools", "profile"));

    @Test
    void sendsTheHandedOverAccessTokenAsABearer() {
        assertThat(strategy(SESSION).headers()).containsExactly(
                java.util.Map.entry("Authorization", "Bearer access-1"));
    }

    @Test
    void leasesTheHandedOverRefreshGrant() {
        Optional<RefreshGrant> grant = strategy(SESSION).refreshGrantStore().orElseThrow()
                .withExclusiveGrant(LiveRefreshGrant::grant);

        assertThat(grant).contains(new RefreshGrant(ISSUER, Optional.of(RESOURCE),
                new OAuthClient("client-1", Optional.of("secret-1"), ClientType.CONFIDENTIAL_REGISTERED),
                "refresh-1", List.of("mcp:tools", "profile")));
    }

    @Test
    void adoptingIssuedTokensReplacesTheAccessAndRefreshTokens() {
        AuthStrategy strategy = strategy(SESSION);

        strategy.refreshGrantStore().orElseThrow().withExclusiveGrant(live -> {
            live.adopt(new IssuedTokens("access-2", Optional.of("refresh-2"), Duration.ofHours(1)));
            return true;
        });

        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer access-2");
        assertThat(refreshToken(strategy)).contains("refresh-2");
    }

    @Test
    void adoptingTokensWithoutARefreshTokenKeepsTheCurrentOne() {
        AuthStrategy strategy = strategy(SESSION);

        strategy.refreshGrantStore().orElseThrow().withExclusiveGrant(live -> {
            live.adopt(new IssuedTokens("access-2", Optional.empty(), Duration.ofHours(1)));
            return true;
        });

        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer access-2");
        assertThat(refreshToken(strategy)).contains("refresh-1");
    }

    @Test
    void aSessionWithoutARefreshTokenOffersNoGrantStore() {
        CommandOAuthSession accessOnly = new CommandOAuthSession("access-1", null, null, null, null, null, null, null);

        AuthStrategy strategy = strategy(accessOnly);

        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer access-1");
        assertThat(strategy.refreshGrantStore()).isEmpty();
    }

    @Test
    void theExtensionDoesNotRefreshAHandedOverSessionByItself() {
        AuthStrategy strategy = strategy(SESSION);

        assertThat(strategy.supportsRefresh()).isFalse();
        assertThat(strategy.refresh()).isFalse();
    }

    @Test
    void oneCheckAtATimeHoldsTheGrant() throws Exception {
        AuthStrategy strategy = strategy(SESSION);
        CountDownLatch holding = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService checks = Executors.newFixedThreadPool(2);
        try {
            Future<Boolean> first = checks.submit(() -> strategy.refreshGrantStore().orElseThrow()
                    .withExclusiveGrant(live -> {
                        holding.countDown();
                        await(release);
                        return true;
                    }).orElseThrow());
            assertThat(holding.await(5, TimeUnit.SECONDS)).isTrue();
            Future<Boolean> second = checks.submit(() -> strategy.refreshGrantStore().orElseThrow()
                    .withExclusiveGrant(live -> true).orElseThrow());

            assertThatThrownBy(() -> second.get(200, TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);
            release.countDown();
            assertThat(first.get(5, TimeUnit.SECONDS)).isTrue();
            assertThat(second.get(5, TimeUnit.SECONDS)).isTrue();
        } finally {
            checks.shutdownNow();
        }
    }

    @Test
    void aHandedOverSessionIsAnOAuthIdentity() {
        assertThat(CommandAuth.handedOver(SESSION).kind()).isEqualTo(IdentityAuthKind.OAUTH);
    }

    @Test
    void neverPrintsTokensOrTheClientSecret() {
        assertThat(SESSION.toString()).doesNotContain("access-1", "refresh-1", "secret-1").contains("client-1");
        assertThat(CommandAuth.handedOver(SESSION).toString()).doesNotContain("access-1", "refresh-1", "secret-1");
    }

    @Test
    void aRefreshTokenNeedsTheClientThatOwnsIt() {
        assertThatThrownBy(() -> new CommandOAuthSession("a", "r", ISSUER, null, null, null, null, null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void aHandedOverSessionExcludesABearerTokenOrHeaders() {
        assertThatThrownBy(() -> new CommandAuth("t", java.util.Map.of(), SESSION))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CommandAuth(null, java.util.Map.of("X-Api-Key", "k"), SESSION))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static AuthStrategy strategy(CommandOAuthSession session) {
        return CommandAuth.handedOver(session).strategy();
    }

    private static Optional<String> refreshToken(AuthStrategy strategy) {
        return strategy.refreshGrantStore().orElseThrow().withExclusiveGrant(live -> live.grant().refreshToken());
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
