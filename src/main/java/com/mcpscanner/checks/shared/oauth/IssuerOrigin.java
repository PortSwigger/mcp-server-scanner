package com.mcpscanner.checks.shared.oauth;

import java.net.URI;
import java.util.Arrays;
import java.util.Optional;

public final class IssuerOrigin {

    public record Endpoint(String role, Optional<URI> uri) {

        public static Endpoint of(String role, URI uri) {
            return new Endpoint(role, Optional.of(uri));
        }

        boolean leaves(URI issuer) {
            return uri.filter(endpoint -> !HttpUris.sameOrigin(issuer, endpoint)).isPresent();
        }
    }

    private IssuerOrigin() {
    }

    public static Optional<String> whyEndpointsLeave(URI issuer, Endpoint... endpoints) {
        return Arrays.stream(endpoints)
                .filter(endpoint -> endpoint.leaves(issuer))
                .findFirst()
                .map(endpoint -> "the authorization server's " + endpoint.role() + " endpoint "
                        + endpoint.uri().orElseThrow() + " is not on the origin of its issuer "
                        + HttpUris.origin(issuer));
    }
}
