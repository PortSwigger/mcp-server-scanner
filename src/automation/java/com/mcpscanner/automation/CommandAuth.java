package com.mcpscanner.automation;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.BearerTokenAuthStrategy;
import com.mcpscanner.auth.CustomHeaderAuthStrategy;
import com.mcpscanner.auth.NoAuthStrategy;
import com.mcpscanner.identity.IdentityAuthKind;

import java.util.Map;

public record CommandAuth(String bearerToken, Map<String, String> headers) {

    public static final CommandAuth NONE = new CommandAuth(null, Map.of());

    public CommandAuth {
        headers = headers == null ? Map.of() : Map.copyOf(headers);
        if (bearerToken != null && !headers.isEmpty()) {
            throw new IllegalArgumentException("Give a bearer token or custom headers, not both");
        }
    }

    public AuthStrategy strategy() {
        if (bearerToken != null) {
            return new BearerTokenAuthStrategy(bearerToken);
        }
        return headers.isEmpty() ? new NoAuthStrategy() : new CustomHeaderAuthStrategy(headers);
    }

    public IdentityAuthKind kind() {
        if (bearerToken != null) {
            return IdentityAuthKind.BEARER;
        }
        return headers.isEmpty() ? IdentityAuthKind.NONE : IdentityAuthKind.CUSTOM_HEADERS;
    }
}
