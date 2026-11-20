package com.mcpscanner.checks.shared.auth;

import com.mcpscanner.auth.AuthHeaderNames;
import com.mcpscanner.auth.AuthStrategy;

import java.util.Map;
import java.util.Optional;

public record FabricatedCredential(String header, String value) {

    private static final String PREFIX = "invalid_";
    private static final String BEARER = "Bearer ";

    public static FabricatedCredential of(AuthStrategy strategy, String canary) {
        String token = PREFIX + canary;
        return CustomCredentialHeaders.of(strategy).stream().findFirst()
                .map(header -> new FabricatedCredential(header, token))
                .orElseGet(() -> new FabricatedCredential(AuthHeaderNames.AUTHORIZATION, BEARER + token));
    }

    public Optional<String> customHeader() {
        return AuthHeaderNames.AUTHORIZATION.equalsIgnoreCase(header) ? Optional.empty() : Optional.of(header);
    }

    public Map<String, String> headers() {
        return Map.of(header, value);
    }
}
