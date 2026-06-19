package com.mcpscanner.auth.oauth;

import java.util.Optional;

public record OAuthSession(
        OAuthTokens tokens,
        String clientId,
        String clientSecret,
        Optional<String> registrationAccessToken,
        Optional<String> registrationClientUri) {

    public static OAuthSession withoutDcrCredentials(OAuthTokens tokens, String clientId, String clientSecret) {
        return new OAuthSession(tokens, clientId, clientSecret, Optional.empty(), Optional.empty());
    }
}
