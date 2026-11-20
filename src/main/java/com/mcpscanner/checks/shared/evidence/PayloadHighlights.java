package com.mcpscanner.checks.shared.evidence;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import com.mcpscanner.http.TextMarkers;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public final class PayloadHighlights {

    private static final int CONTEXT_BYTES = 16;

    private PayloadHighlights() {
    }

    public static HttpRequestResponse ofPayload(HttpRequestResponse exchange, AuditInsertionPoint point,
                                                String payload) {
        if (exchange == null) {
            return null;
        }
        List<Marker> anchored = anchoredMarkers(exchange, point, payload);
        return anchored.isEmpty() ? TextMarkers.inRequest(exchange, insertedTexts(point, payload))
                : exchange.withRequestMarkers(anchored);
    }

    public static HttpRequestResponse ofRequestText(HttpRequestResponse exchange, Collection<String> texts) {
        return TextMarkers.inRequest(exchange, texts);
    }

    public static HttpRequestResponse ofProof(HttpRequestResponse exchange, Collection<String> proofs) {
        return TextMarkers.inResponse(exchange, proofs);
    }

    private static List<Marker> anchoredMarkers(HttpRequestResponse exchange, AuditInsertionPoint point,
                                                String payload) {
        if (exchange.request() == null) {
            return List.of();
        }
        try {
            ByteArray value = ByteArray.byteArray(payload);
            byte[] built = point.buildHttpRequestWithPayload(value).toByteArray().getBytes();
            byte[] sent = exchange.request().toByteArray().getBytes();
            List<Range> highlights = point.issueHighlights(value).stream()
                    .filter(range -> within(range, built.length))
                    .toList();
            List<Marker> markers = highlights.stream()
                    .map(range -> locatedInContext(built, range, sent))
                    .flatMap(Optional::stream)
                    .toList();
            return markers.size() == highlights.size() ? markers : List.of();
        } catch (RuntimeException unsupported) {
            return List.of();
        }
    }

    private static Optional<Marker> locatedInContext(byte[] built, Range range, byte[] sent) {
        int contextStart = Math.max(0, range.startIndexInclusive() - CONTEXT_BYTES);
        int contextEnd = Math.min(built.length, range.endIndexExclusive() + CONTEXT_BYTES);
        int found = indexOf(sent, Arrays.copyOfRange(built, contextStart, contextEnd));
        if (found < 0) {
            return Optional.empty();
        }
        int start = found + range.startIndexInclusive() - contextStart;
        return Optional.of(Marker.marker(start, start + range.endIndexExclusive() - range.startIndexInclusive()));
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int start = 0; start + needle.length <= haystack.length; start++) {
            if (Arrays.equals(haystack, start, start + needle.length, needle, 0, needle.length)) {
                return start;
            }
        }
        return -1;
    }

    private static List<String> insertedTexts(AuditInsertionPoint point, String payload) {
        try {
            ByteArray value = ByteArray.byteArray(payload);
            byte[] built = point.buildHttpRequestWithPayload(value).toByteArray().getBytes();
            return point.issueHighlights(value).stream()
                    .filter(range -> within(range, built.length))
                    .map(range -> new String(Arrays.copyOfRange(built, range.startIndexInclusive(),
                            range.endIndexExclusive()), StandardCharsets.UTF_8))
                    .toList();
        } catch (RuntimeException unsupported) {
            return List.of();
        }
    }

    private static boolean within(Range range, int length) {
        return range.startIndexInclusive() >= 0 && range.startIndexInclusive() < range.endIndexExclusive()
                && range.endIndexExclusive() <= length;
    }
}
