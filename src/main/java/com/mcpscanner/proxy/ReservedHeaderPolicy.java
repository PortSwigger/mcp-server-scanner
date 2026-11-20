package com.mcpscanner.proxy;

import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.ScannerSentinels;

import java.util.Set;

final class ReservedHeaderPolicy {

    private static final Set<String> TRANSPORT_FRAMING = McpHeaders.caseInsensitive(
            "host", "content-length", "content-type", "accept", "connection", "upgrade",
            "transfer-encoding", "http2-settings", "proxy-connection", "expect", "keep-alive",
            "te", "trailer", "trailers", "date", "from", "via", "warning");

    private static final Set<String> PROXY_CREDENTIALS = McpHeaders.caseInsensitive("proxy-authorization");

    private static final Set<String> LOCAL_SERVER_PSEUDO = McpHeaders.caseInsensitive("remote-addr", "http-client-ip");

    private static final Set<String> CLIENT_SYNTHETIC = McpHeaders.caseInsensitive("user-agent");

    private ReservedHeaderPolicy() {}

    static boolean isTransportFraming(String name) {
        return TRANSPORT_FRAMING.contains(name);
    }

    static boolean isScannerSentinel(String name) {
        return ScannerSentinels.STRIPPED_BEFORE_UPSTREAM.contains(name);
    }

    static boolean isForwardable(String name) {
        return !isTransportFraming(name) && !isScannerSentinel(name) && !PROXY_CREDENTIALS.contains(name)
                && !LOCAL_SERVER_PSEUDO.contains(name);
    }

    static boolean isForwardableOverSession(String name) {
        return isForwardable(name)
                && !name.equalsIgnoreCase("Authorization")
                && !name.equalsIgnoreCase(McpHeaders.PROTOCOL_VERSION)
                && !name.equalsIgnoreCase(McpHeaders.SESSION_ID);
    }

    static boolean reachesServerOverSession(String name) {
        return isForwardableOverSession(name) && !McpHeaders.isOperationHeader(name);
    }

    static boolean isIdentityBearing(String name) {
        return !isTransportFraming(name) && !isScannerSentinel(name)
                && !McpHeaders.isProtocolHeader(name) && !McpHeaders.isOperationHeader(name)
                && !CLIENT_SYNTHETIC.contains(name)
                && !LOCAL_SERVER_PSEUDO.contains(name);
    }
}
