package com.mcpscanner.checks.shared.oauth;

import java.util.Optional;

public record ClientSecret(String value, ClientSecretMethod method) {

    static Optional<ClientSecret> issuedIn(JsonDocument registration) {
        return registration.text("client_secret").map(secret -> new ClientSecret(secret,
                ClientSecretMethod.named(registration.text("token_endpoint_auth_method"))));
    }

    @Override
    public String toString() {
        return "ClientSecret[" + method + "]";
    }
}
