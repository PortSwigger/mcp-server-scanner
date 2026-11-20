package com.mcpscanner.automation;

import com.mcpscanner.auth.AuthHeaders;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.grant.IssuedTokens;
import com.mcpscanner.auth.grant.LiveRefreshGrant;
import com.mcpscanner.auth.grant.RefreshGrant;
import com.mcpscanner.auth.grant.RefreshGrantStore;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;

final class HandedOverOAuthStrategy implements AuthStrategy, RefreshGrantStore {

    private final ReentrantLock grantLease = new ReentrantLock();
    private volatile String accessToken;
    private volatile Optional<RefreshGrant> grant;

    HandedOverOAuthStrategy(String accessToken, Optional<RefreshGrant> grant) {
        this.accessToken = accessToken;
        this.grant = grant;
    }

    @Override
    public Map<String, String> headers() {
        return Map.of(AuthHeaders.AUTHORIZATION_HEADER, AuthHeaders.BEARER_PREFIX + accessToken);
    }

    @Override
    public Optional<RefreshGrantStore> refreshGrantStore() {
        return grant.map(held -> this);
    }

    @Override
    public <T> Optional<T> withExclusiveGrant(Function<LiveRefreshGrant, T> work) {
        grantLease.lock();
        try {
            return grant.isEmpty() ? Optional.empty() : Optional.ofNullable(work.apply(new HeldGrant()));
        } finally {
            grantLease.unlock();
        }
    }

    private void adopt(IssuedTokens tokens) {
        accessToken = tokens.accessToken();
        tokens.refreshToken().ifPresent(this::rotate);
    }

    private void rotate(String refreshToken) {
        grant = grant.map(held -> new RefreshGrant(held.issuer(), held.resource(), held.client(), refreshToken,
                held.requestedScopes()));
    }

    private final class HeldGrant implements LiveRefreshGrant {

        @Override
        public RefreshGrant grant() {
            return grant.orElseThrow();
        }

        @Override
        public void adopt(IssuedTokens tokens) {
            HandedOverOAuthStrategy.this.adopt(tokens);
        }
    }
}
