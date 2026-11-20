package com.mcpscanner.http;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;

public final class TextMarkers {

    private static final int MAX_MARKERS = 16;

    private TextMarkers() {
    }

    public static HttpRequestResponse inRequest(HttpRequestResponse exchange, Collection<String> texts) {
        if (exchange == null || exchange.request() == null || texts.isEmpty()) {
            return exchange;
        }
        List<Marker> markers = find(exchange.request().toByteArray(), encoded(texts));
        return markers.isEmpty() ? exchange : exchange.withRequestMarkers(markers);
    }

    public static HttpRequestResponse inResponse(HttpRequestResponse exchange, Collection<String> texts) {
        if (exchange == null || exchange.response() == null || texts.isEmpty()) {
            return exchange;
        }
        List<Marker> markers = find(exchange.response().toByteArray(), encoded(texts));
        return markers.isEmpty() ? exchange : exchange.withResponseMarkers(markers);
    }

    public static HttpRequestResponse carriedOver(HttpRequestResponse from, HttpRequestResponse to) {
        return responseCarriedOver(from, requestCarriedOver(from, to));
    }

    static HttpRequestResponse requestCarriedOver(HttpRequestResponse from, HttpRequestResponse to) {
        if (from.requestMarkers().isEmpty() || to.request() == null) {
            return to;
        }
        List<Marker> markers = AnchoredMarkers.relocated(bytesOf(from.request().toByteArray()),
                from.requestMarkers(), bytesOf(to.request().toByteArray()));
        return markers.isEmpty() ? to : to.withRequestMarkers(markers);
    }

    static HttpRequestResponse responseCarriedOver(HttpRequestResponse from, HttpRequestResponse to) {
        if (from.responseMarkers().isEmpty() || from.response() == null || to.response() == null) {
            return to;
        }
        List<Marker> markers = AnchoredMarkers.relocated(bytesOf(from.response().toByteArray()),
                from.responseMarkers(), bytesOf(to.response().toByteArray()));
        return markers.isEmpty() ? to : to.withResponseMarkers(markers);
    }

    private static List<byte[]> encoded(Collection<String> texts) {
        return texts.stream().filter(text -> !text.isEmpty())
                .map(text -> text.getBytes(StandardCharsets.UTF_8)).toList();
    }

    private static byte[] bytesOf(ByteArray message) {
        return message == null || message.getBytes() == null ? new byte[0] : message.getBytes();
    }

    private static List<Marker> find(ByteArray message, List<byte[]> texts) {
        byte[] haystack = bytesOf(message);
        boolean[] taken = new boolean[haystack.length];
        List<int[]> spans = new ArrayList<>();
        for (byte[] needle : texts) {
            for (int start = indexOf(haystack, needle, 0); start >= 0 && spans.size() < MAX_MARKERS;
                 start = indexOf(haystack, needle, start + needle.length)) {
                if (claim(taken, start, start + needle.length)) {
                    spans.add(new int[] {start, start + needle.length});
                }
            }
        }
        return spans.stream().sorted(Comparator.comparingInt(span -> span[0]))
                .map(span -> Marker.marker(span[0], span[1])).toList();
    }

    private static boolean claim(boolean[] taken, int start, int end) {
        for (int index = start; index < end; index++) {
            if (taken[index]) {
                return false;
            }
        }
        Arrays.fill(taken, start, end, true);
        return true;
    }

    private static int indexOf(byte[] haystack, byte[] needle, int from) {
        if (needle.length == 0) {
            return -1;
        }
        for (int start = from; start <= haystack.length - needle.length; start++) {
            if (matchesAt(haystack, needle, start)) {
                return start;
            }
        }
        return -1;
    }

    private static boolean matchesAt(byte[] haystack, byte[] needle, int start) {
        for (int offset = 0; offset < needle.length; offset++) {
            if (haystack[start + offset] != needle[offset]) {
                return false;
            }
        }
        return true;
    }
}
