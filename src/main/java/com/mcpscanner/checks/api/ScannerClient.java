package com.mcpscanner.checks.api;

import com.mcpscanner.checks.shared.oauth.ClientCredentials;
import com.mcpscanner.checks.shared.oauth.ClientSecret;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public record ScannerClient(URI issuer, String clientId, RegisteredClientName clientName, URI redirectUri,
                            Set<String> grantedScopes, Optional<String> softwareId, Optional<ClientSecret> secret) {

    public ScannerClient {
        Objects.requireNonNull(issuer, "issuer must not be null");
        Objects.requireNonNull(clientId, "clientId must not be null");
        Objects.requireNonNull(clientName, "clientName must not be null");
        Objects.requireNonNull(redirectUri, "redirectUri must not be null");
        grantedScopes = Set.copyOf(grantedScopes);
        Objects.requireNonNull(softwareId, "softwareId must not be null");
        Objects.requireNonNull(secret, "secret must not be null");
    }

    public ScannerClient(URI issuer, String clientId, RegisteredClientName clientName, URI redirectUri,
                         Set<String> grantedScopes, Optional<String> softwareId) {
        this(issuer, clientId, clientName, redirectUri, grantedScopes, softwareId, Optional.empty());
    }

    public ScannerClient withSecret(ClientSecret clientSecret) {
        return new ScannerClient(issuer, clientId, clientName, redirectUri, grantedScopes, softwareId,
                Optional.of(clientSecret));
    }

    public ClientCredentials credentials() {
        return new ClientCredentials(clientId, secret);
    }
}
