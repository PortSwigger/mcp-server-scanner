package com.mcpscanner.auth.oauth.safety;

import java.net.URI;

/**
 * Describes why a destination URL is being fetched, so the {@link SuspiciousDestinationGate}
 * can render meaningful context in its prompts and event-log lines.
 *
 * @param label         human-readable label such as "Protected Resource Metadata".
 * @param mcpEndpoint   the configured MCP endpoint that scoped this connection — used to
 *                      detect cross-origin redirects from the MCP host.
 * @param sourceUrl     the URL that introduced the destination (e.g. the PRM document URL
 *                      that referenced an authorization_servers entry). Nullable when the
 *                      destination is the first hop.
 */
public record FetchPurpose(String label, URI mcpEndpoint, URI sourceUrl) {

    public static FetchPurpose of(String label, URI mcpEndpoint) {
        return new FetchPurpose(label, mcpEndpoint, null);
    }

    public static FetchPurpose of(String label, URI mcpEndpoint, URI sourceUrl) {
        return new FetchPurpose(label, mcpEndpoint, sourceUrl);
    }
}
