package com.mcpscanner.ui.identities;

import com.mcpscanner.identity.ConnectionFreshness;
import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.StaleConnection;
import com.mcpscanner.identity.ToolCallRefusals;
import com.mcpscanner.identity.credentials.IdentityCredentialServices;
import com.mcpscanner.identity.credentials.IdentityCredentials;
import com.mcpscanner.identity.credentials.SignInQueue;
import com.mcpscanner.identity.discovery.ComparedDiscovery;
import com.mcpscanner.identity.discovery.IdentityListings;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;

public record IdentityUiServices(IdentityRegistry registry,
                                 IdentityCredentialServices credentialServices,
                                 IdentityListings listings,
                                 ComparedDiscovery discovery,
                                 ToolCallRefusals refusals,
                                 IdentityConnection connection,
                                 ReconnectPrompt reconnectPrompt) {

    public IdentityUiServices {
        Objects.requireNonNull(registry, "registry");
        Objects.requireNonNull(credentialServices, "credentialServices");
        Objects.requireNonNull(listings, "listings");
        Objects.requireNonNull(discovery, "discovery");
        Objects.requireNonNull(refusals, "refusals");
        Objects.requireNonNull(connection, "connection");
        Objects.requireNonNull(reconnectPrompt, "reconnectPrompt");
    }

    IdentityCredentials credentials() {
        return credentialServices.credentials();
    }

    SignInQueue signIns() {
        return credentialServices.signIns();
    }

    boolean isConnected() {
        return connection.isConnected();
    }

    Optional<StaleConnection> staleConnection() {
        return connection.connectedIdentity().flatMap(new ConnectionFreshness(registry)::check);
    }

    public Runnable onChange(Runnable listener) {
        Consumer<String> signInListener = identityId -> listener.run();
        registry.addListener(listener);
        listings.addListener(listener);
        refusals.addListener(listener);
        signIns().addListener(signInListener);
        return () -> {
            registry.removeListener(listener);
            listings.removeListener(listener);
            refusals.removeListener(listener);
            signIns().removeListener(signInListener);
        };
    }
}
