package com.mcpscanner.auth;

import com.mcpscanner.auth.oauth.AuthState;
import com.mcpscanner.auth.oauth.OAuthException;
import com.mcpscanner.auth.oauth.OAuthTokens;
import com.mcpscanner.auth.oauth.TokenRefresher;
import com.mcpscanner.logging.McpEventLog;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public final class OAuthAuthCodeStrategy implements AuthStrategy {

    private static final Duration REFRESH_SKEW = Duration.ofSeconds(30);
    private static final int MAX_CONSECUTIVE_REFRESH_FAILURES = 3;

    private final URI issuer;
    private final List<String> scopes;
    private final String clientId;
    private final String clientSecret;
    private final URI mcpResource;
    private final Clock clock;
    private final TokenRefresher refresher;
    private final McpEventLog eventLog;

    private volatile AccessToken accessToken;
    private volatile RefreshToken refreshToken;
    private volatile Instant expiresAt;
    private volatile String subject;
    private int consecutiveRefreshFailures;
    private volatile boolean terminallyFailed;
    private volatile Runnable terminalFailureListener = () -> {};

    public OAuthAuthCodeStrategy(URI issuer,
                                  List<String> scopes,
                                  String clientId,
                                  String clientSecret,
                                  URI mcpResource,
                                  OAuthTokens initialTokens,
                                  TokenRefresher refresher,
                                  Clock clock,
                                  McpEventLog eventLog) {
        this.issuer = issuer;
        this.scopes = scopes != null ? List.copyOf(scopes) : List.of();
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.mcpResource = mcpResource;
        this.refresher = refresher;
        this.clock = clock;
        this.eventLog = eventLog;
        this.accessToken = initialTokens.accessToken();
        this.refreshToken = initialTokens.refreshToken();
        this.expiresAt = initialTokens.expiresAt();
        this.subject = initialTokens.subject();
    }

    @Override
    public Map<String, String> headers() {
        AccessToken token;
        synchronized (this) {
            guardedRefresh();
            token = accessToken;
        }
        return Map.of(AuthHeaders.AUTHORIZATION_HEADER, AuthHeaders.BEARER_PREFIX + token.getValue());
    }

    @Override
    public boolean supportsRefresh() {
        return true;
    }

    @Override
    public synchronized boolean refresh() {
        return guardedRefresh();
    }

    private boolean guardedRefresh() {
        if (terminallyFailed) {
            return false;
        }
        if (!needsRefresh()) {
            return true;
        }
        try {
            performTokenRefresh();
            consecutiveRefreshFailures = 0;
            return true;
        } catch (OAuthException e) {
            consecutiveRefreshFailures++;
            eventLog.error("OAuth refresh failed (" + consecutiveRefreshFailures + "/"
                    + MAX_CONSECUTIVE_REFRESH_FAILURES + "): " + e.getMessage(), e);
            if (consecutiveRefreshFailures >= MAX_CONSECUTIVE_REFRESH_FAILURES) {
                tripCircuitBreaker();
            }
            return false;
        }
    }

    public boolean isTerminallyFailed() {
        return terminallyFailed;
    }

    public void setTerminalFailureListener(Runnable listener) {
        this.terminalFailureListener = listener != null ? listener : () -> {};
    }

    private void tripCircuitBreaker() {
        terminallyFailed = true;
        eventLog.error("OAuth refresh circuit breaker tripped after "
                + MAX_CONSECUTIVE_REFRESH_FAILURES + " consecutive failures; "
                + "reconnect to continue");
        try {
            terminalFailureListener.run();
        } catch (RuntimeException listenerFailure) {
            eventLog.warn("OAuth terminal-failure listener threw "
                    + listenerFailure.getClass().getSimpleName()
                    + ": " + listenerFailure.getMessage());
        }
    }

    private void performTokenRefresh() {
        if (refreshToken == null) {
            throw new OAuthException("No refresh token available; reconnect to re-authorize");
        }
        OAuthTokens fresh = refresher.refresh(issuer, clientId, clientSecret, refreshToken, mcpResource);
        this.accessToken = fresh.accessToken();
        this.refreshToken = fresh.refreshToken() != null ? fresh.refreshToken() : this.refreshToken;
        this.expiresAt = fresh.expiresAt();
        if (fresh.subject() != null) {
            this.subject = fresh.subject();
        }
    }

    public AuthState snapshot() {
        Instant now = Instant.now(clock);
        boolean valid = expiresAt != null && now.isBefore(expiresAt);
        return new AuthState(subject, expiresAt, valid);
    }

    public URI issuer() {
        return issuer;
    }

    public String clientId() {
        return clientId;
    }

    public RefreshToken refreshToken() {
        return refreshToken;
    }

    public List<String> scopes() {
        return scopes;
    }

    private boolean needsRefresh() {
        return expiresAt == null || Instant.now(clock).isAfter(expiresAt.minus(REFRESH_SKEW));
    }
}
