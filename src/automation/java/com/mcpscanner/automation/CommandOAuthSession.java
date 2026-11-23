package com.mcpscanner.automation;

import com.mcpscanner.auth.grant.ClientType;
import com.mcpscanner.auth.grant.OAuthClient;
import com.mcpscanner.auth.grant.RefreshGrant;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

public record CommandOAuthSession(String accessToken, String refreshToken, URI issuer, URI resource, String clientId,
                                  String clientSecret, ClientType clientType, List<String> requestedScopes) {

    public CommandOAuthSession {
        Objects.requireNonNull(accessToken, "accessToken");
        requestedScopes = requestedScopes == null ? List.of() : List.copyOf(requestedScopes);
        if (refreshToken != null) {
            Objects.requireNonNull(issuer, "issuer");
            Objects.requireNonNull(clientId, "clientId");
            Objects.requireNonNull(clientType, "clientType");
        }
    }

    public static CommandOAuthSession of(String accessToken, Optional<RefreshGrant> grant) {
        return grant.map(held -> new CommandOAuthSession(accessToken, held.refreshToken(), held.issuer(),
                        held.resource().orElse(null), held.client().clientId(), held.client().secret().orElse(null),
                        held.client().type(), held.requestedScopes()))
                .orElseGet(() -> new CommandOAuthSession(accessToken, null, null, null, null, null, null, null));
    }

    HandedOverOAuthStrategy strategy() {
        return new HandedOverOAuthStrategy(accessToken, Optional.ofNullable(refreshToken).map(this::grant));
    }

    private RefreshGrant grant(String heldRefreshToken) {
        return new RefreshGrant(issuer, Optional.ofNullable(resource),
                new OAuthClient(clientId, Optional.ofNullable(clientSecret), clientType), heldRefreshToken,
                requestedScopes);
    }

    @Override
    public String toString() {
        return "CommandOAuthSession[issuer=" + issuer + ", clientId=" + clientId + ", clientType=" + clientType
                + ", refreshable=" + (refreshToken != null) + ", tokens=redacted]";
    }
}
