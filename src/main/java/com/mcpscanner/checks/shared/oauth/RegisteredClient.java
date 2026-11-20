package com.mcpscanner.checks.shared.oauth;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;
import java.util.Optional;

public record RegisteredClient(String clientId, List<String> redirectUris, HttpRequestResponse evidence,
                               Optional<ClientManagement> management, Optional<ClientSecret> secret) {

    public RegisteredClient {
        redirectUris = List.copyOf(redirectUris);
    }

    public RegisteredClient(String clientId, List<String> redirectUris, HttpRequestResponse evidence,
                            Optional<ClientManagement> management) {
        this(clientId, redirectUris, evidence, management, Optional.empty());
    }

    public ClientCredentials credentials() {
        return new ClientCredentials(clientId, secret);
    }

    public boolean lists(String redirectUri) {
        return redirectUris.stream().anyMatch(redirectUri::equalsIgnoreCase);
    }
}
