package com.mcpscanner.identity.discovery;

public interface PreComparisonDiscovery {

    PreComparisonDiscovery NONE = () -> { };

    void discoverMissing();

    default PreComparisonDiscovery withSyntheticListings() {
        return this;
    }
}
