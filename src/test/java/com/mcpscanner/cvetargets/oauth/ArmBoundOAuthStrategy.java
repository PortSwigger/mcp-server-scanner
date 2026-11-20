package com.mcpscanner.cvetargets.oauth;

import com.mcpscanner.auth.AccessToken;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;
import com.mcpscanner.auth.grant.RefreshGrantStore;
import com.mcpscanner.cvetargets.manifest.AuthorizationCodeGrant;
import com.mcpscanner.cvetargets.run.ArmBoundAuth;
import org.awaitility.core.ConditionTimeoutException;

import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

import static org.awaitility.Awaitility.await;

public final class ArmBoundOAuthStrategy implements AuthStrategy, ArmBoundAuth, HandsOverOAuthSession {

    private static final Duration RETRY_PAUSE = Duration.ofSeconds(1);

    private final Function<URI, OAuthAuthCodeStrategy> login;
    private volatile OAuthAuthCodeStrategy live;
    private volatile AuthStrategy session;

    public ArmBoundOAuthStrategy(AuthorizationCodeGrant grant) {
        this(new AuthorizationCodeLogin(grant)::login);
    }

    ArmBoundOAuthStrategy(Function<URI, OAuthAuthCodeStrategy> login) {
        this.login = login;
    }

    @Override
    public void bind(URI armEndpoint, Duration timeout) {
        AtomicReference<RuntimeException> lastFailure = new AtomicReference<>();
        try {
            await().atMost(timeout).pollDelay(Duration.ZERO).pollInterval(RETRY_PAUSE).pollInSameThread()
                    .until(() -> loggedIn(armEndpoint, lastFailure));
        } catch (ConditionTimeoutException timedOut) {
            throw new IllegalStateException("OAuth login to " + armEndpoint + " did not succeed within " + timeout,
                    lastFailure.get());
        }
    }

    private boolean loggedIn(URI armEndpoint, AtomicReference<RuntimeException> lastFailure) {
        try {
            live = login.apply(armEndpoint);
            session = live;
            return true;
        } catch (RuntimeException failure) {
            lastFailure.set(failure);
            return false;
        }
    }

    @Override
    public synchronized OAuthSessionHandover handOver() {
        if (live == null || session != live) {
            throw new IllegalStateException("only a live OAuth session that is still the harness's is handed over");
        }
        OAuthSessionHandover handover = live.withExclusiveGrant(held ->
                        new OAuthSessionHandover(currentAccessToken(), Optional.of(held.grant())))
                .orElseGet(() -> new OAuthSessionHandover(currentAccessToken(), Optional.empty()));
        session = new RelinquishedOAuthSession(handover.accessToken());
        return handover;
    }

    private String currentAccessToken() {
        return live.currentToken().map(AccessToken::value)
                .orElseThrow(() -> new IllegalStateException("the OAuth session holds no access token"));
    }

    @Override
    public Map<String, String> headers() {
        return bound().headers();
    }

    @Override
    public Set<String> contributedHeaderNames() {
        return bound().contributedHeaderNames();
    }

    @Override
    public boolean supportsRefresh() {
        return bound().supportsRefresh();
    }

    @Override
    public boolean refresh() {
        return bound().refresh();
    }

    @Override
    public boolean isTerminallyFailed() {
        return bound().isTerminallyFailed();
    }

    @Override
    public Optional<RefreshGrantStore> refreshGrantStore() {
        return bound().refreshGrantStore();
    }

    private AuthStrategy bound() {
        if (session == null) {
            throw new IllegalStateException("the OAuth session is obtained when the arm starts");
        }
        return session;
    }
}
