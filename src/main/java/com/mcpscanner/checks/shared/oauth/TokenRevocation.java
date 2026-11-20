package com.mcpscanner.checks.shared.oauth;

import com.mcpscanner.logging.McpEventLog;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class TokenRevocation {

    private static final int REVOKED = 200;

    private final OAuthHttp http;
    private final Optional<URI> revocationEndpoint;
    private final URI tokenEndpoint;
    private final McpEventLog eventLog;

    public TokenRevocation(OAuthHttp http, Optional<URI> revocationEndpoint, URI tokenEndpoint,
                           McpEventLog eventLog) {
        this.http = http;
        this.revocationEndpoint = revocationEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.eventLog = eventLog;
    }

    public void revoke(String clientId, List<IssuedToken> tokens) {
        revoke(ClientCredentials.publicClient(clientId), tokens);
    }

    public void revoke(ClientCredentials client, List<IssuedToken> tokens) {
        if (tokens.isEmpty()) {
            return;
        }
        if (revocationEndpoint.isEmpty()) {
            logLeft(client.clientId(), tokens.size(), "the authorization server advertises no revocation endpoint");
            return;
        }
        long unrevoked = tokens.stream().filter(token -> !revoked(revocationEndpoint.get(), client, token)).count();
        if (unrevoked > 0) {
            logLeft(client.clientId(), unrevoked, "revocation at " + revocationEndpoint.get() + " was refused or unanswered");
        }
    }

    private boolean revoked(URI endpoint, ClientCredentials client, IssuedToken token) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("token", token.value());
        form.put("token_type_hint", token.typeHint());
        return http.postForm(endpoint, AuthorizationParameters.encode(client.form(form)), "application/json",
                        client.headers())
                .filter(exchange -> exchange.response().statusCode() == REVOKED)
                .isPresent();
    }

    private void logLeft(String clientId, long count, String cause) {
        eventLog.error(count + " OAuth token(s) left on " + HttpUris.origin(tokenEndpoint) + " for client_id "
                + clientId + " (" + cause + "); revoke them or delete the client manually");
    }
}
