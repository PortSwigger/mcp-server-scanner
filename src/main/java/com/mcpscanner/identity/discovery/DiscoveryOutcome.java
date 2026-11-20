package com.mcpscanner.identity.discovery;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;
import java.util.Objects;

public sealed interface DiscoveryOutcome {

    enum Discovering implements DiscoveryOutcome { INSTANCE }

    record Listed(IdentityListing listing, List<HttpRequestResponse> toolsList) implements DiscoveryOutcome {
        public Listed {
            Objects.requireNonNull(listing, "listing");
            toolsList = List.copyOf(toolsList);
        }

        public Listed(IdentityListing listing) {
            this(listing, List.of());
        }
    }

    record Failed(String reason) implements DiscoveryOutcome {
        public Failed {
            Objects.requireNonNull(reason, "reason");
        }
    }
}
