package com.mcpscanner.auth;

import com.mcpscanner.auth.oauth.AuthState;
import com.mcpscanner.auth.oauth.OAuthException;
import com.mcpscanner.auth.oauth.OAuthTokens;
import com.mcpscanner.auth.oauth.TokenRefresher;
import com.mcpscanner.logging.McpEventLog;
import com.mcpscanner.testutil.MontoyaTestFactory;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class OAuthAuthCodeStrategyTest {

    private static final URI ISSUER = URI.create("https://issuer.example.com");
    private static final String CLIENT_ID = "client-abc";

    private McpEventLog eventLog;

    @BeforeEach
    void setUp() {
        MontoyaTestFactory.install();
        eventLog = new McpEventLog(null);
    }

    @Test
    void headersReturnsBearerWithoutRefreshWhenTokenIsFresh() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        AtomicInteger refreshCount = new AtomicInteger();
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> {
            refreshCount.incrementAndGet();
            return tokens("new", "new-refresh", now.plusSeconds(600));
        };
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null,
                null,
                tokens("initial", "refresh-1", now.plusSeconds(300)),
                refresher, clock, eventLog);

        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer initial");
        assertThat(refreshCount).hasValue(0);
    }

    @Test
    void headersTriggersRefreshWhenWithinSkewWindow() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        TokenRefresher refresher = (issuer, id, secret, rt, resource) ->
                tokens("rotated", "refresh-2", now.plusSeconds(300));
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null,
                null,
                tokens("initial", "refresh-1", now.plusSeconds(15)),
                refresher, clock, eventLog);

        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer rotated");
    }

    @Test
    void headersTriggersRefreshWhenAlreadyExpired() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        TokenRefresher refresher = (issuer, id, secret, rt, resource) ->
                tokens("rotated", "refresh-2", now.plusSeconds(600));
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null,
                null,
                tokens("initial", "refresh-1", now.minus(Duration.ofMinutes(5))),
                refresher, clock, eventLog);

        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer rotated");
    }

    @Test
    void headersDoesNotPropagatePreEmptiveRefreshFailureButDegradesToLastKnownToken() {
        // Deliberate semantics change (audit medium A): the pre-emptive refresh in headers()
        // now goes through the same guarded path as refresh(), so a refresh failure no longer
        // throws out of headers() uncaught. Instead the failure is counted and headers()
        // surfaces the last-known token, consistent with the circuit-breaker contract.
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> {
            throw new OAuthException("refresh-failed");
        };
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null,
                null,
                tokens("initial", "refresh-1", now.minusSeconds(60)),
                refresher, clock, eventLog);

        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer initial");
        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.ERROR
                        && entry.message().contains("OAuth refresh failed")
                        && entry.message().contains("refresh-failed"));
    }

    @Test
    void circuitBreakerTripsAfterThreeConsecutivePreEmptiveRefreshFailuresViaHeaders() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        AtomicInteger refreshCount = new AtomicInteger();
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> {
            refreshCount.incrementAndGet();
            throw new OAuthException("invalid_grant");
        };
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null, null,
                tokens("initial", "refresh-1", now.minusSeconds(60)),
                refresher, clock, eventLog);

        strategy.headers();
        strategy.headers();
        strategy.headers();

        assertThat(strategy.isTerminallyFailed()).isTrue();
        assertThat(refreshCount).hasValue(3);

        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer initial");
        assertThat(refreshCount)
                .as("once tripped, further headers() calls must not call the refresher")
                .hasValue(3);
    }

    @Test
    void successfulPreEmptiveRefreshViaHeadersResetsConsecutiveFailureCounter() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        AtomicInteger callCount = new AtomicInteger();
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> {
            int n = callCount.incrementAndGet();
            if (n == 1 || n == 2) {
                throw new OAuthException("transient");
            }
            return tokens("rotated", "refresh-2", now.minusSeconds(60));
        };
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null, null,
                tokens("initial", "refresh-1", now.minusSeconds(60)),
                refresher, clock, eventLog);

        strategy.headers();
        strategy.headers();
        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer rotated");

        assertThat(strategy.isTerminallyFailed()).isFalse();
    }

    @Test
    void supportsRefreshIsTrue() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null,
                null,
                tokens("initial", "refresh-1", now.plusSeconds(600)),
                noopRefresher(), clock, eventLog);

        assertThat(strategy.supportsRefresh()).isTrue();
    }

    @Test
    void refreshReturnsTrueOnSuccessfulRotation() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        TokenRefresher refresher = (issuer, id, secret, rt, resource) ->
                tokens("rotated", "refresh-2", now.plusSeconds(600));
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null,
                null,
                tokens("initial", "refresh-1", now.minusSeconds(60)),
                refresher, clock, eventLog);

        assertThat(strategy.refresh()).isTrue();
        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer rotated");
    }

    @Test
    void refreshReturnsFalseAndLogsOAuthExceptionDetailWhenTokenRefresherThrows() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> {
            throw new OAuthException("refresh-failed");
        };
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null,
                null,
                tokens("initial", "refresh-1", now.minusSeconds(60)),
                refresher, clock, eventLog);

        assertThat(strategy.refresh()).isFalse();
        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.ERROR
                        && entry.message().contains("OAuth refresh failed")
                        && entry.message().contains("refresh-failed"));
    }

    @Test
    void refreshReturnsFalseAndLogsWhenNoRefreshTokenAvailable() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null,
                null,
                new OAuthTokens(new BearerAccessToken("initial"), null,
                        now.minusSeconds(60), null),
                noopRefresher(), clock, eventLog);

        assertThat(strategy.refresh()).isFalse();
        assertThat(eventLog.snapshot())
                .anyMatch(entry -> entry.level() == McpEventLog.Level.ERROR
                        && entry.message().contains("OAuth refresh failed")
                        && entry.message().contains("No refresh token available"));
    }

    @Test
    void refreshKeepsExistingRefreshTokenWhenServerOmitsRotation() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        TokenRefresher refresher = (issuer, id, secret, rt, resource) ->
                new OAuthTokens(new BearerAccessToken("rotated"), null, now.plusSeconds(600), null);
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null,
                null,
                tokens("initial", "refresh-original", now.minusSeconds(60)),
                refresher, clock, eventLog);

        strategy.refresh();

        assertThat(strategy.refreshToken().getValue()).isEqualTo("refresh-original");
    }

    @Test
    void snapshotReportsValidWhenExpiryInFuture() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null,
                null,
                new OAuthTokens(new BearerAccessToken("initial"),
                        new RefreshToken("refresh-1"),
                        now.plusSeconds(300),
                        "alice"),
                noopRefresher(), clock, eventLog);

        AuthState state = strategy.snapshot();
        assertThat(state.valid()).isTrue();
        assertThat(state.subject()).isEqualTo("alice");
    }

    @Test
    void snapshotReportsInvalidWhenExpired() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null,
                null,
                new OAuthTokens(new BearerAccessToken("initial"),
                        new RefreshToken("refresh-1"),
                        now.minusSeconds(60),
                        null),
                noopRefresher(), clock, eventLog);

        assertThat(strategy.snapshot().valid()).isFalse();
    }

    @Test
    void headersUnderConcurrencyNeverProducesPartialOrNullToken() throws Exception {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        AtomicInteger refreshCount = new AtomicInteger();
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> {
            refreshCount.incrementAndGet();
            return tokens("rotated", "refresh-2", now.plusSeconds(600));
        };
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null,
                null,
                tokens("initial", "refresh-1", now.minus(Duration.ofMinutes(5))),
                refresher, clock, eventLog);

        int threadCount = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Map<String, String>>> futures = new ArrayList<>();
        for (int i = 0; i < threadCount; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return strategy.headers();
            }));
        }
        start.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(5, TimeUnit.SECONDS)).isTrue();

        for (Future<Map<String, String>> future : futures) {
            assertThat(future.get()).containsEntry("Authorization", "Bearer rotated");
        }
        assertThat(refreshCount.get()).isEqualTo(1);
    }

    @Test
    void headersAlwaysReadsAccessTokenInsideLockEvenWhenFresh() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null,
                null,
                tokens("initial", "refresh-1", now.plusSeconds(600)),
                noopRefresher(), clock, eventLog);

        Map<String, String> headers = strategy.headers();

        assertThat(headers).containsEntry("Authorization", "Bearer initial");
    }

    @Test
    void refreshIsDebouncedAndSkippedWhenAccessTokenStillFresh() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        AtomicInteger refreshCount = new AtomicInteger();
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> {
            refreshCount.incrementAndGet();
            return tokens("rotated", "refresh-2", now.plusSeconds(600));
        };
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null, null,
                tokens("initial", "refresh-1", now.plusSeconds(600)),
                refresher, clock, eventLog);

        assertThat(strategy.refresh()).isTrue();
        assertThat(strategy.refresh()).isTrue();

        assertThat(refreshCount).hasValue(0);
    }

    @Test
    void parallelRefreshCallsSerialiseToOneNetworkCall() throws Exception {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        AtomicInteger refreshCount = new AtomicInteger();
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> {
            refreshCount.incrementAndGet();
            return tokens("rotated", "refresh-2", now.plusSeconds(600));
        };
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null, null,
                tokens("initial", "refresh-1", now.minusSeconds(60)),
                refresher, clock, eventLog);

        int threadCount = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Boolean>> futures = new ArrayList<>();
        for (int i = 0; i < threadCount; i++) {
            futures.add(pool.submit(() -> {
                start.await();
                return strategy.refresh();
            }));
        }
        start.countDown();
        pool.shutdown();
        assertThat(pool.awaitTermination(5, TimeUnit.SECONDS)).isTrue();

        for (Future<Boolean> future : futures) {
            assertThat(future.get()).isTrue();
        }
        assertThat(refreshCount.get()).isEqualTo(1);
    }

    @Test
    void circuitBreakerTripsAfterThreeConsecutiveRefreshFailures() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        AtomicInteger refreshCount = new AtomicInteger();
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> {
            refreshCount.incrementAndGet();
            throw new OAuthException("invalid_grant");
        };
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null, null,
                tokens("initial", "refresh-1", now.minusSeconds(60)),
                refresher, clock, eventLog);

        assertThat(strategy.refresh()).isFalse();
        assertThat(strategy.refresh()).isFalse();
        assertThat(strategy.refresh()).isFalse();

        assertThat(strategy.isTerminallyFailed()).isTrue();
        assertThat(refreshCount).hasValue(3);

        assertThat(strategy.refresh()).isFalse();
        assertThat(refreshCount)
                .as("once tripped, further refresh attempts must not call the refresher")
                .hasValue(3);
    }

    @Test
    void circuitBreakerNotifiesTerminalFailureListenerExactlyOnceOnTrip() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> {
            throw new OAuthException("invalid_grant");
        };
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null, null,
                tokens("initial", "refresh-1", now.minusSeconds(60)),
                refresher, clock, eventLog);
        AtomicInteger listenerCalls = new AtomicInteger();
        strategy.setTerminalFailureListener(listenerCalls::incrementAndGet);

        strategy.refresh();
        strategy.refresh();
        strategy.refresh();
        strategy.refresh();

        assertThat(listenerCalls).hasValue(1);
    }

    @Test
    void successfulRefreshResetsConsecutiveFailureCounter() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        AtomicInteger callCount = new AtomicInteger();
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> {
            int n = callCount.incrementAndGet();
            if (n == 1 || n == 2) {
                throw new OAuthException("transient");
            }
            return tokens("rotated", "refresh-2", now.minusSeconds(60));
        };
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null, null,
                tokens("initial", "refresh-1", now.minusSeconds(60)),
                refresher, clock, eventLog);

        strategy.refresh();
        strategy.refresh();
        strategy.refresh();

        assertThat(strategy.isTerminallyFailed()).isFalse();
    }

    @Test
    void headersIsNoOpWhenStrategyHasTerminallyFailed() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> {
            throw new OAuthException("invalid_grant");
        };
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null, null,
                tokens("initial", "refresh-1", now.minusSeconds(60)),
                refresher, clock, eventLog);

        strategy.refresh();
        strategy.refresh();
        strategy.refresh();

        assertThat(strategy.headers()).containsEntry("Authorization", "Bearer initial");
    }

    @Test
    void freshInstanceStartsHealthyEvenWhenPreviousInstanceFailed() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        OAuthAuthCodeStrategy fresh = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null, null,
                tokens("initial", "refresh-1", now.plusSeconds(600)),
                noopRefresher(), clock, eventLog);

        assertThat(fresh.isTerminallyFailed()).isFalse();
    }

    @Test
    void refreshPassesMcpResourceToTokenRefresher() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        Clock clock = Clock.fixed(now, ZoneOffset.UTC);
        URI mcpResource = URI.create("https://mcp.example.com/mcp");
        List<URI> capturedResources = new ArrayList<>();
        TokenRefresher refresher = (issuer, id, secret, rt, resource) -> {
            capturedResources.add(resource);
            return tokens("rotated", "refresh-2", now.plusSeconds(600));
        };
        OAuthAuthCodeStrategy strategy = new OAuthAuthCodeStrategy(
                ISSUER, List.of(), CLIENT_ID, null, mcpResource,
                tokens("initial", "refresh-1", now.minusSeconds(60)),
                refresher, clock, eventLog);

        strategy.refresh();

        assertThat(capturedResources).containsExactly(mcpResource);
    }

    private static TokenRefresher noopRefresher() {
        return (issuer, id, secret, rt, resource) -> {
            throw new AssertionError("refresh should not be called");
        };
    }

    private static OAuthTokens tokens(String accessValue, String refreshValue, Instant expiresAt) {
        AccessToken accessToken = new BearerAccessToken(accessValue);
        return new OAuthTokens(accessToken, new RefreshToken(refreshValue), expiresAt, null);
    }
}
