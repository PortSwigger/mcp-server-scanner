package com.mcpscanner.automation;

import com.mcpscanner.auth.oauth.OAuthSignIn;

import java.net.URI;
import java.util.Optional;
import java.util.Set;

public record CommandScannerClient(URI issuer, URI authorizationEndpoint, URI registrationEndpoint, String clientId,
                                   String clientName, URI redirectUri, Set<String> grantedScopes, String softwareId) {

    public CommandScannerClient {
        grantedScopes = grantedScopes == null ? Set.of() : Set.copyOf(grantedScopes);
    }

    OAuthSignIn signInFor(URI resource) {
        return new OAuthSignIn(issuer, authorizationEndpoint, Optional.ofNullable(registrationEndpoint), clientId,
                Optional.ofNullable(clientName).filter(name -> !name.isBlank()), redirectUri, grantedScopes, Optional.ofNullable(softwareId), resource);
    }
}
