package com.mcpscanner.checks.shared.session;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.core.connection.SseSessionIds;

import java.net.URI;
import java.util.List;
import java.util.Optional;

public final class SessionHeaders {

    private SessionHeaders() {
    }

    public static Optional<String> carriedBy(HttpRequest request) {
        return valueIn(request.headers());
    }

    public static Optional<String> legacySseSessionOf(HttpRequest request) {
        return legacySseSessionOf(request.url());
    }

    public static Optional<String> sentLegacySseSessionOf(HttpRequest request) {
        return SseSessionIds.sentFrom(request.url()).or(() -> lastPathSegmentOf(request.url()));
    }

    static Optional<String> legacySseSessionOf(String messageUrl) {
        return SseSessionIds.from(messageUrl).or(() -> lastPathSegmentOf(messageUrl));
    }

    static Optional<String> legacySseSessionOf(String messageUrl, String liveMessageUrl) {
        return SseSessionIds.from(messageUrl).or(() -> samePath(messageUrl, liveMessageUrl)
                ? Optional.empty() : lastPathSegmentOf(messageUrl));
    }

    private static boolean samePath(String messageUrl, String otherMessageUrl) {
        return URI.create(messageUrl).getRawPath().equals(URI.create(otherMessageUrl).getRawPath());
    }

    private static Optional<String> lastPathSegmentOf(String url) {
        String path = URI.create(url).getRawPath();
        String trimmed = path == null ? "" : path.replaceAll("/+$", "");
        String segment = trimmed.substring(trimmed.lastIndexOf('/') + 1);
        return segment.isEmpty() ? Optional.empty() : Optional.of(segment);
    }

    public static Optional<String> issuedBy(HttpRequestResponse exchange) {
        return exchange == null || exchange.response() == null ? Optional.empty()
                : valueIn(exchange.response().headers());
    }

    public static HttpRequest inSession(HttpRequest request, String sessionId) {
        return request.withRemovedHeader(McpHeaders.SESSION_ID).withAddedHeader(McpHeaders.SESSION_ID, sessionId);
    }

    private static Optional<String> valueIn(List<HttpHeader> headers) {
        return headers == null ? Optional.empty() : headers.stream()
                .filter(header -> McpHeaders.SESSION_ID.equalsIgnoreCase(header.name()))
                .map(HttpHeader::value)
                .filter(value -> value != null && !value.isBlank())
                .findFirst();
    }
}
