package com.mcpscanner.auth.oauth;

import com.nimbusds.oauth2.sdk.token.RefreshToken;

import java.net.URI;

@FunctionalInterface
public interface TokenRefresher {

    OAuthTokens refresh(URI issuer, String clientId, String clientSecret, RefreshToken refreshToken, URI mcpResource);
}
