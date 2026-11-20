package com.mcpscanner.checks.catalog.sessionlifecycle;

import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.checks.shared.evidence.PayloadHighlights;
import com.mcpscanner.checks.shared.session.SessionHeaders;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class HandshakeEvidence {

    private HandshakeEvidence() {
    }

    static Optional<HttpRequestResponse> of(HttpRequestResponse exchange, List<String> issuedIds) {
        return issuedInResponse(exchange, issuedIds).or(() -> issuedInMessageUrl(exchange, issuedIds));
    }

    private static Optional<HttpRequestResponse> issuedInResponse(HttpRequestResponse exchange,
                                                                  List<String> issuedIds) {
        return SessionHeaders.issuedBy(exchange).filter(issuedIds::contains)
                .map(id -> PayloadHighlights.ofProof(exchange, List.of(id)));
    }

    private static Optional<HttpRequestResponse> issuedInMessageUrl(HttpRequestResponse exchange,
                                                                    List<String> issuedIds) {
        return SessionHeaders.legacySseSessionOf(exchange.request()).filter(issuedIds::contains)
                .flatMap(id -> SessionHeaders.sentLegacySseSessionOf(exchange.request()))
                .map(sent -> markedInRequestLine(exchange, sent));
    }

    private static HttpRequestResponse markedInRequestLine(HttpRequestResponse exchange, String sentId) {
        String requestLine = requestLine(exchange);
        return firstMatch(queryValue(sentId), requestLine)
                .or(() -> firstMatch(lastPathSegment(sentId), requestLine))
                .map(match -> exchange.withRequestMarkers(List.of(Marker.marker(match.start(1), match.end(1)))))
                .orElseGet(() -> PayloadHighlights.ofRequestText(exchange, List.of(sentId)));
    }

    private static Pattern queryValue(String sentId) {
        return Pattern.compile("[?&][^=&\\s]+=(" + Pattern.quote(sentId) + ")(?=[\\s&#]|$)");
    }

    private static Pattern lastPathSegment(String sentId) {
        return Pattern.compile("/(" + Pattern.quote(sentId) + ")/*(?=[\\s?#]|$)");
    }

    private static Optional<Matcher> firstMatch(Pattern pattern, String text) {
        Matcher matcher = pattern.matcher(text);
        return matcher.find() ? Optional.of(matcher) : Optional.empty();
    }

    private static String requestLine(HttpRequestResponse exchange) {
        String request = new String(exchange.request().toByteArray().getBytes(), StandardCharsets.ISO_8859_1);
        int end = request.indexOf('\n');
        return end < 0 ? request : request.substring(0, end);
    }
}
