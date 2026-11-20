package com.mcpscanner.cvetargets.oauth;

import com.mcpscanner.auth.AuthHeaders;
import com.mcpscanner.auth.AuthStrategy;

import java.util.Map;

final class RelinquishedOAuthSession implements AuthStrategy {

    private final String lastAccessToken;

    RelinquishedOAuthSession(String lastAccessToken) {
        this.lastAccessToken = lastAccessToken;
    }

    @Override
    public Map<String, String> headers() {
        return Map.of(AuthHeaders.AUTHORIZATION_HEADER, AuthHeaders.BEARER_PREFIX + lastAccessToken);
    }
}
