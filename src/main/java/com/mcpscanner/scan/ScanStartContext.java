package com.mcpscanner.scan;

import java.util.Map;
import java.util.Objects;

/**
 * Snapshot of live connection state passed to {@link ScanStartCheck} instances at
 * scan-start time. Carries the resolved MCP endpoint URL and the connect-time
 * scanner headers (Authorization, Mcp-Session-Id, etc.) so checks can build
 * authenticated probes without reaching into the session class directly.
 *
 * <p>Kept as a plain record so the {@code scan/} package has no dependency on
 * {@code client/} (which would close the {@code checks/ -> scan/ -> client/ ->
 * checks/} cycle). The launcher is the only place that maps a
 * {@code McpScannerSession} onto this record.
 */
public record ScanStartContext(String endpoint, Map<String, String> headers) {

    public ScanStartContext {
        Objects.requireNonNull(endpoint, "endpoint must not be null");
        Objects.requireNonNull(headers, "headers must not be null");
        headers = Map.copyOf(headers);
    }
}
