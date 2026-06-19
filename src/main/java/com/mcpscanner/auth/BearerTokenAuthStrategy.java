package com.mcpscanner.auth;

import java.util.Map;

public class BearerTokenAuthStrategy implements AuthStrategy {

    private final String token;

    public BearerTokenAuthStrategy(String token) {
        rejectControlBytes(token);
        this.token = token;
    }

    private static void rejectControlBytes(String token) {
        if (token != null
                && (token.indexOf('\r') >= 0 || token.indexOf('\n') >= 0 || token.indexOf('\0') >= 0)) {
            throw new IllegalArgumentException(
                    "Bearer token contains illegal control characters (CR, LF, or NUL)");
        }
    }

    @Override
    public Map<String, String> headers() {
        return Map.of(AuthHeaders.AUTHORIZATION_HEADER, AuthHeaders.BEARER_PREFIX + token);
    }
}
