package com.mcpscanner.checks.shared.oauth;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.net.URI;
import java.util.Optional;

public final class AuthorizationServerDiscovery {

    private final ProtectedResourceLocator resources;
    private final AuthorizationServerMetadataFetcher metadata;

    public AuthorizationServerDiscovery(OAuthHttp http) {
        this.resources = new ProtectedResourceLocator(http);
        this.metadata = new AuthorizationServerMetadataFetcher(http);
    }

    public Optional<AuthorizationServer> discover(HttpRequestResponse base) {
        return HttpUris.parse(base.request().url())
                .flatMap(endpoint -> discover(endpoint, BearerChallenge.of(base.response())));
    }

    private Optional<AuthorizationServer> discover(URI mcpEndpoint, BearerChallenge challenge) {
        Optional<ProtectedResource> resource = resources.locate(mcpEndpoint, challenge);
        URI issuer = resource.map(ProtectedResource::authorizationServer)
                .orElseGet(() -> URI.create(HttpUris.origin(mcpEndpoint)));
        URI resourceUri = resource.flatMap(ProtectedResource::resource).orElse(mcpEndpoint);
        Optional<String> scope = challenge.scope().or(() -> resource.flatMap(ProtectedResource::scope));
        return metadata.fetch(issuer, document -> document.webUri("authorization_endpoint")
                .map(authorization -> new AuthorizationServer(
                        document.webUri("issuer").orElse(issuer),
                        authorization,
                        document.webUri("registration_endpoint"),
                        document.webUri("token_endpoint"),
                        document.webUri("revocation_endpoint"),
                        resourceUri,
                        scope,
                        document.texts("scopes_supported"))));
    }
}
