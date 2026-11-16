package com.mcpscanner.mcp;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

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
    public static final String AUDIT_CAPABILITY_HEADER = "X-Mcp-Scanner-Audit-Capability";
    public static final String KEEP_SESSION_HEADER = "X-Mcp-Scanner-Keep-Session";

    public static final String DIRECT_DELIVERY_HEADER = "X-Mcp-Scanner-Direct";

    public static final String IDENTITY_HEADER = "X-Mcp-Scanner-Identity";

    public static final String GENERATED_REGISTRATION_HEADER = "X-Mcp-Scanner-Registration";

    public static final String EXCHANGE_HEADER = "X-Mcp-Scanner-Exchange";

    public static final String ROUTED_HEADER = "X-Mcp-Scanner-Routed";

    public static final String SENTINEL_VALUE = "1";

    public static final Set<String> ROUTES_TO_PROXY = McpHeaders.caseInsensitive(
            AUDIT_CAPABILITY_HEADER, STRIP_AUTH_HEADER, IDENTITY_HEADER);

    public static final Set<String> STRIPPED_BEFORE_UPSTREAM = McpHeaders.caseInsensitive(
            AUDIT_CAPABILITY_HEADER, STRIP_AUTH_HEADER, IDENTITY_HEADER, KEEP_SESSION_HEADER, ROUTED_HEADER);

    public static final Set<String> ALL = withStrippedBeforeUpstream(
            DIRECT_DELIVERY_HEADER, GENERATED_REGISTRATION_HEADER, EXCHANGE_HEADER);

    private ScannerSentinels() {}

    private static Set<String> withStrippedBeforeUpstream(String... others) {
        return McpHeaders.caseInsensitive(Stream.concat(STRIPPED_BEFORE_UPSTREAM.stream(), Stream.of(others))
                .toArray(String[]::new));
    }

    public static Map<String, String> stripAuthOnly() {
        return Map.of(STRIP_AUTH_HEADER, SENTINEL_VALUE);
    }

    public static Map<String, String> directDeliveryOnly() {
        return Map.of(DIRECT_DELIVERY_HEADER, SENTINEL_VALUE);
    }

    public static Map<String, String> withStripAuth(String headerName, String headerValue) {
        Map<String, String> overrides = new LinkedHashMap<>();
        overrides.put(headerName, headerValue);
        overrides.put(STRIP_AUTH_HEADER, SENTINEL_VALUE);
        return overrides;
    }
}
