package com.mcpscanner.proxy;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.client.ConnectedEndpoint;
import com.mcpscanner.client.TransportType;
import com.mcpscanner.mcp.FramedOperation;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.McpRequestDetector;
import com.mcpscanner.mcp.ScannerSentinels;

import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Collectors;

public final class ProxyDroppedChanges {

    private final ConnectedEndpoint endpoint;
    private final ProxyRouting routing;
    private final Predicate<String> issuedSessionIds;

    public ProxyDroppedChanges(ConnectedEndpoint endpoint, Predicate<String> issuedSessionIds) {
        this.endpoint = Objects.requireNonNull(endpoint);
        this.routing = new ProxyRouting(endpoint);
        this.issuedSessionIds = Objects.requireNonNull(issuedSessionIds);
    }

    public boolean dropsEveryChange(HttpRequest base, HttpRequest altered) {
        return forwardsOverTheSession(base) && forwardsOverTheSession(altered)
                && JsonRpcRequestId.sameApartFromId(base.body().getBytes(), altered.body().getBytes())
                && headersReachingServer(base).equals(headersReachingServer(altered));
    }

    private boolean forwardsOverTheSession(HttpRequest request) {
        Map<String, String> headers = headerMap(request);
        return endpoint.transportType() != TransportType.SSE
                && routing.answersLocally(request)
                && request.hasHeader(ScannerSentinels.AUDIT_CAPABILITY_HEADER)
                && !SentinelHeaders.hasStripAuth(headers)
                && !SentinelHeaders.hasIdentity(headers)
                && presentsNoForeignSession(request)
                && !McpRequestDetector.isInitializeBody(request.bodyToString());
    }

    private boolean presentsNoForeignSession(HttpRequest request) {
        return !request.hasHeader(McpHeaders.SESSION_ID)
                || issuedSessionIds.test(request.headerValue(McpHeaders.SESSION_ID));
    }

    private static Map<String, String> headersReachingServer(HttpRequest request) {
        return headerMap(request).entrySet().stream()
                .filter(header -> ReservedHeaderPolicy.reachesServerOverSession(header.getKey())
                        || FramedOperation.records(header.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private static Map<String, String> headerMap(HttpRequest request) {
        return request.headers().stream().collect(Collectors.toMap(
                header -> header.name().toLowerCase(Locale.ROOT), HttpHeader::value,
                (first, repeated) -> first + "\n" + repeated));
    }
}
