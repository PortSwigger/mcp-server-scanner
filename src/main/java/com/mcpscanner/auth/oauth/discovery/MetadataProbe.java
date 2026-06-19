package com.mcpscanner.auth.oauth.discovery;

import java.net.URI;
import java.util.Optional;

public interface MetadataProbe {
    Optional<DiscoveredMetadata> probe(URI mcpResource);
}
