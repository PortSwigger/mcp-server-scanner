package com.mcpscanner.access;

import com.mcpscanner.http.UpstreamExchanges;
import com.mcpscanner.identity.discovery.PreComparisonDiscovery;

import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;

public record CheckAccessOptions(UpstreamExchanges upstreamExchanges, Supplier<AccessSnapshot> results,
                                 PreComparisonDiscovery discovery, ListingAudit listingAudit) {

    public static final CheckAccessOptions DEFAULTS = new CheckAccessOptions(UpstreamExchanges.NONE,
            () -> new AccessSnapshot(false, List.of(), List.of()), PreComparisonDiscovery.NONE, ListingAudit.NONE);

    public CheckAccessOptions {
        Objects.requireNonNull(upstreamExchanges, "upstreamExchanges");
        Objects.requireNonNull(results, "results");
        Objects.requireNonNull(discovery, "discovery");
        Objects.requireNonNull(listingAudit, "listingAudit");
    }

    public CheckAccessOptions withUpstreamExchanges(UpstreamExchanges exchanges) {
        return new CheckAccessOptions(exchanges, results, discovery, listingAudit);
    }

    public CheckAccessOptions withResults(Supplier<AccessSnapshot> snapshot) {
        return new CheckAccessOptions(upstreamExchanges, snapshot, discovery, listingAudit);
    }

    public CheckAccessOptions withDiscovery(PreComparisonDiscovery missing) {
        return new CheckAccessOptions(upstreamExchanges, results, missing, listingAudit);
    }

    public CheckAccessOptions withListingAudit(ListingAudit audit) {
        return new CheckAccessOptions(upstreamExchanges, results, discovery, audit);
    }
}
