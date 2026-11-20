package com.mcpscanner.auth.oauth;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public record OAuthSignIn(URI issuer, URI authorizationEndpoint, Optional<URI> registrationEndpoint,
                          String clientId, Optional<String> clientName, URI redirectUri, Set<String> grantedScopes,
                          Optional<String> softwareId, URI resource, Optional<String> clientSecret) {

    public OAuthSignIn {
        Objects.requireNonNull(issuer, "issuer must not be null");
        Objects.requireNonNull(authorizationEndpoint, "authorizationEndpoint must not be null");
        Objects.requireNonNull(registrationEndpoint, "registrationEndpoint must not be null");
        Objects.requireNonNull(clientId, "clientId must not be null");
        Objects.requireNonNull(clientName, "clientName must not be null");
        Objects.requireNonNull(redirectUri, "redirectUri must not be null");
        grantedScopes = Set.copyOf(grantedScopes);
        Objects.requireNonNull(softwareId, "softwareId must not be null");
        Objects.requireNonNull(resource, "resource must not be null");
        Objects.requireNonNull(clientSecret, "clientSecret must not be null");
    }

    public OAuthSignIn(URI issuer, URI authorizationEndpoint, Optional<URI> registrationEndpoint, String clientId,
                       Optional<String> clientName, URI redirectUri, Set<String> grantedScopes,
                       Optional<String> softwareId, URI resource) {
        this(issuer, authorizationEndpoint, registrationEndpoint, clientId, clientName, redirectUri, grantedScopes,
                softwareId, resource, Optional.empty());
    }

    public OAuthSignIn withGrantedScopes(Set<String> scopes) {
        return new OAuthSignIn(issuer, authorizationEndpoint, registrationEndpoint, clientId, clientName, redirectUri,
                scopes, softwareId, resource, clientSecret);
    }

    @Override
    public String toString() {
        return "OAuthSignIn[issuer=" + issuer + ", clientId=" + clientId + ", clientName=" + clientName
                + ", redirectUri=" + redirectUri + ", grantedScopes=" + grantedScopes + ", resource=" + resource
                + ", confidential=" + clientSecret.isPresent() + "]";
    }

    public boolean sameClientAs(OAuthSignIn other) {
        return issuer.equals(other.issuer) && clientId.equals(other.clientId) && resource.equals(other.resource);
    }
}
