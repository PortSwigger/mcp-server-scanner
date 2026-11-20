package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import com.mcpscanner.checks.shared.oauth.ClientCredentials;
import com.mcpscanner.checks.shared.oauth.ClientMetadata;
import com.mcpscanner.checks.shared.oauth.ProbeCallback;
import com.mcpscanner.checks.shared.oauth.ProbeClientRegistrar;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

record ProbeClient(ClientCredentials credentials, URI callback) {

    private static final String CLIENT_NAME = "Burp MCP authorization consent probe";

    ProbeClient(String clientId, URI callback) {
        this(ClientCredentials.publicClient(clientId), callback);
    }

    static Optional<ProbeClient> register(ProbeClientRegistrar registrar) {
        URI callback = ProbeCallback.loopback("scancheck-consent-" + UUID.randomUUID());
        return register(registrar, ClientMetadata.codeGrant(CLIENT_NAME, List.of(callback.toString())), callback);
    }

    static Optional<ProbeClient> register(ProbeClientRegistrar registrar, ClientMetadata metadata, URI callback) {
        return registrar.registerAddingRefreshGrantIfRequired(metadata).client()
                .map(client -> new ProbeClient(client.credentials(), callback));
    }

    String clientId() {
        return credentials.clientId();
    }

    boolean isCallback(URI location) {
        return ProbeCallback.matches(callback, location);
    }
}
