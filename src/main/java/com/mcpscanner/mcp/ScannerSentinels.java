package com.mcpscanner.mcp;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Sentinel header names that flow scanner-side intent through Burp into the local proxy.
 *
 * <p>Lives in {@code mcp/} (a leaf package) so both {@code proxy/} and {@code checks/} can
 * reference the same constant without crossing layering rules.
 */
public final class ScannerSentinels {

    // Signals to SseProxyServer that the scanner deliberately wants NO auth-bearing headers
    // injected upstream. Header absence alone cannot express this because the proxy would
    // otherwise re-inject the session's stored Authorization/Cookie/custom auth headers
    // (which would silently mask every auth-bypass probe). The proxy strips this header
    // before forwarding the request upstream.
    public static final String STRIP_AUTH_HEADER = "X-Mcp-Scanner-Strip-Auth";

    private static final String SENTINEL_VALUE = "1";

    private ScannerSentinels() {}

    public static Map<String, String> stripAuthOnly() {
        return Map.of(STRIP_AUTH_HEADER, SENTINEL_VALUE);
    }

    public static Map<String, String> withStripAuth(String headerName, String headerValue) {
        Map<String, String> overrides = new LinkedHashMap<>();
        overrides.put(headerName, headerValue);
        overrides.put(STRIP_AUTH_HEADER, SENTINEL_VALUE);
        return overrides;
    }
}
