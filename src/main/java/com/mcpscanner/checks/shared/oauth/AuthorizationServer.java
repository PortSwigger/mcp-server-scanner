package com.mcpscanner.checks.shared.oauth;

import java.net.URI;
import java.util.List;
import java.util.Optional;

public record AuthorizationServer(
        URI issuer,
        URI authorizationEndpoint,
        Optional<URI> registrationEndpoint,
        Optional<URI> tokenEndpoint,
        Optional<URI> revocationEndpoint,
        URI resource,
        Optional<String> scope,
        List<String> scopesSupported) {

    public AuthorizationServer {
        scopesSupported = List.copyOf(scopesSupported);
    }

    public Optional<String> whyEndpointsLeaveIssuerOrigin() {
        return IssuerOrigin.whyEndpointsLeave(issuer,
                IssuerOrigin.Endpoint.of("authorization", authorizationEndpoint),
                new IssuerOrigin.Endpoint("registration", registrationEndpoint),
                new IssuerOrigin.Endpoint("token", tokenEndpoint),
                new IssuerOrigin.Endpoint("revocation", revocationEndpoint));
    }
}
