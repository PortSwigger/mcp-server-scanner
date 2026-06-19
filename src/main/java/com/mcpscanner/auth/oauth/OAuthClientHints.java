package com.mcpscanner.auth.oauth;

import java.net.URI;
import java.time.Duration;
import java.util.List;

public record OAuthClientHints(URI issuer,
                                List<String> scopes,
                                String clientId,
                                String clientSecret,
                                boolean allowDcr,
                                int redirectPort,
                                Duration timeout) {

    public static final int DEFAULT_REDIRECT_PORT = 0;
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(120);

    public OAuthClientHints {
        scopes = scopes != null ? List.copyOf(scopes) : List.of();
        if (timeout == null) {
            timeout = DEFAULT_TIMEOUT;
        }
    }
}
