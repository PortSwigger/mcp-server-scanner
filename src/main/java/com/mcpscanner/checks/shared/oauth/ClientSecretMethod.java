package com.mcpscanner.checks.shared.oauth;

import java.util.Optional;

public enum ClientSecretMethod {
    BASIC,
    POST;

    private static final String BASIC_METHOD = "client_secret_basic";

    static ClientSecretMethod named(Optional<String> tokenEndpointAuthMethod) {
        return tokenEndpointAuthMethod.filter(method -> !BASIC_METHOD.equals(method)).isPresent() ? POST : BASIC;
    }
}
