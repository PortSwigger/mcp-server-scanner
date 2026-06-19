package com.mcpscanner.ui;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.CustomHeaderAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.auth.OAuthAuthCodeStrategy;

import java.util.Map;

/**
 * Builds the {@link AuthStrategy} for a selected auth type from plain inputs
 * (bearer token text, custom-header rows, the published OAuth strategy). Lives
 * in ui/ because it references the UI auth-type constants on
 * {@link ServerConfigPanel}; ui→auth is the allowed dependency direction.
 * Custom headers are validated through {@link HeaderValidator} so injection
 * rules stay in one place.
 */
public final class AuthStrategyFactory {

    private final HeaderValidator headerValidator = new HeaderValidator();

    public AuthStrategy create(String authType,
                               String bearerToken,
                               Map<String, String> customHeaders,
                               OAuthAuthCodeStrategy publishedOauthStrategy) {
        return switch (authType) {
            case ServerConfigPanel.AUTH_BEARER -> new BearerTokenAuthStrategy(bearerToken.trim());
            case ServerConfigPanel.AUTH_CUSTOM -> new CustomHeaderAuthStrategy(headerValidator.validate(customHeaders));
            case ServerConfigPanel.AUTH_OAUTH -> requireEstablished(publishedOauthStrategy);
            default -> new NoAuthStrategy();
        };
    }

    private static AuthStrategy requireEstablished(OAuthAuthCodeStrategy publishedOauthStrategy) {
        if (publishedOauthStrategy == null) {
            throw new IllegalStateException(
                    "OAuth selected but no authorization strategy has been established");
        }
        return publishedOauthStrategy;
    }
}
