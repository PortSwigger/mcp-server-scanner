package com.mcpscanner.ui.state;

import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.auth.oauth.OAuthClientHints;
import com.mcpscanner.client.TransportType;

import java.net.URI;

public record ConnectAttempt(String endpoint,
                             TransportType transport,
                             String host,
                             String authType,
                             AuthStrategy snapshotAuth,
                             OAuthClientHints oauthHints,
                             URI mcpResource) {

    public static ConnectAttempt withSnapshot(String endpoint, TransportType transport, String host,
                                              String authType, AuthStrategy snapshotAuth) {
        return new ConnectAttempt(endpoint, transport, host, authType, snapshotAuth, null, null);
    }

    public static ConnectAttempt withOauth(String endpoint, TransportType transport, String host,
                                           String authType, OAuthClientHints hints, URI mcpResource) {
        return new ConnectAttempt(endpoint, transport, host, authType, null, hints, mcpResource);
    }
}

