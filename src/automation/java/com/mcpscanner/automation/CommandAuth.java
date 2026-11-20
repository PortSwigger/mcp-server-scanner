package com.mcpscanner.automation;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.CustomHeaderAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.identity.IdentityAuthKind;

import java.util.Map;
import java.util.stream.Stream;

public record CommandAuth(String bearerToken, Map<String, String> headers, CommandOAuthSession oauthSession) {

    public static final CommandAuth NONE = new CommandAuth(null, Map.of());

    public CommandAuth {
        headers = headers == null ? Map.of() : Map.copyOf(headers);
        if (Stream.of(bearerToken != null, !headers.isEmpty(), oauthSession != null).filter(given -> given).count() > 1) {
            throw new IllegalArgumentException("Give one of a bearer token, custom headers or an OAuth session");
        }
    }

    public CommandAuth(String bearerToken, Map<String, String> headers) {
        this(bearerToken, headers, null);
    }

    public static CommandAuth handedOver(CommandOAuthSession session) {
        return new CommandAuth(null, Map.of(), session);
    }

    public AuthStrategy strategy() {
        if (oauthSession != null) {
            return oauthSession.strategy();
        }
        if (bearerToken != null) {
            return new BearerTokenAuthStrategy(bearerToken);
        }
        return headers.isEmpty() ? new NoAuthStrategy() : new CustomHeaderAuthStrategy(headers);
    }

    public IdentityAuthKind kind() {
        if (oauthSession != null) {
            return IdentityAuthKind.OAUTH;
        }
        if (bearerToken != null) {
            return IdentityAuthKind.BEARER;
        }
        return headers.isEmpty() ? IdentityAuthKind.NONE : IdentityAuthKind.CUSTOM_HEADERS;
    }
}
