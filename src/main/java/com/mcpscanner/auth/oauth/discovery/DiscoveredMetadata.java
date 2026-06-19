package com.mcpscanner.auth.oauth.discovery;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;

import java.net.URI;
import java.util.List;

public record DiscoveredMetadata(URI issuer, DiscoverySource source, AuthorizationServerMetadata asMetadata) {

    public List<String> advertisedScopes() {
        Scope scope = asMetadata != null ? asMetadata.getScopes() : null;
        if (scope == null) {
            return List.of();
        }
        return scope.stream().map(Object::toString).toList();
    }
}
