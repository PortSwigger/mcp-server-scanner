package com.mcpscanner.ui;

import com.mcpscanner.identity.IdentityRegistry;
import com.mcpscanner.identity.ToolCallRefusals;
import com.mcpscanner.identity.credentials.IdentityCredentialServices;
import com.mcpscanner.identity.credentials.ScopeApprovals;
import com.mcpscanner.identity.credentials.SharedAuthSettings;
import com.mcpscanner.identity.discovery.ComparedDiscovery;
import com.mcpscanner.identity.discovery.IdentityListings;
import com.mcpscanner.ui.identities.ReconnectPrompt;

import java.util.Objects;
import java.util.function.BiFunction;

public record IdentityDependencies(IdentityRegistry registry,
                                   IdentityListings listings,
                                   ComparedDiscovery discovery,
                                   ToolCallRefusals refusals,
                                   BiFunction<SharedAuthSettings, ScopeApprovals,
                                           IdentityCredentialServices>
                                           credentialServices,
                                   ReconnectPrompt reconnectPrompt) {

    public IdentityDependencies {
        Objects.requireNonNull(registry, "registry");
        Objects.requireNonNull(listings, "listings");
        Objects.requireNonNull(discovery, "discovery");
        Objects.requireNonNull(refusals, "refusals");
        Objects.requireNonNull(credentialServices, "credentialServices");
        Objects.requireNonNull(reconnectPrompt, "reconnectPrompt");
    }
}
