package com.mcpscanner.http;

import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;

import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.stream.IntStream;

final class AnchoredMarkers {

    private static final int[] CONTEXT_WIDTHS = {16, 8, 4, 2, 1, 0};

    private final byte[] from;
    private final byte[] to;
    private final boolean[] taken;

    private AnchoredMarkers(byte[] from, byte[] to) {
        this.from = from;
        this.to = to;
        this.taken = new boolean[to.length];
    }

    static List<Marker> relocated(byte[] from, List<Marker> markers, byte[] to) {
        AnchoredMarkers anchors = new AnchoredMarkers(from, to);
        return markers.stream()
                .map(Marker::range)
                .filter(anchors::withinSource)
                .map(anchors::relocate)
                .flatMap(Optional::stream)
                .sorted(Comparator.comparingInt(marker -> marker.range().startIndexInclusive()))
                .toList();
    }

    private boolean withinSource(Range range) {
        return range.startIndexInclusive() >= 0 && range.startIndexInclusive() < range.endIndexExclusive()
                && range.endIndexExclusive() <= from.length;
    }

    private Optional<Marker> relocate(Range range) {
        for (int width : CONTEXT_WIDTHS) {
            Optional<Marker> found = inContext(range, width, width)
                    .or(() -> inContext(range, width, 0))
                    .or(() -> inContext(range, 0, width));
            if (found.isPresent()) {
                claim(found.get().range());
                return found;
            }
        }
        return Optional.empty();
    }

    private Optional<Marker> inContext(Range range, int before, int after) {
        int contextStart = Math.max(0, range.startIndexInclusive() - before);
        int contextEnd = Math.min(from.length, range.endIndexExclusive() + after);
        byte[] context = Arrays.copyOfRange(from, contextStart, contextEnd);
        int markedOffset = range.startIndexInclusive() - contextStart;
        int length = range.endIndexExclusive() - range.startIndexInclusive();
        return occurrences(context)
                .map(found -> found + markedOffset)
                .filter(start -> free(start, start + length))
                .boxed()
                .min((left, right) -> Integer.compare(distanceFrom(range, left), distanceFrom(range, right)))
                .map(start -> Marker.marker(start, start + length));
    }

    private boolean free(int start, int end) {
        return IntStream.range(start, end).noneMatch(index -> taken[index]);
    }

    private void claim(Range range) {
        Arrays.fill(taken, range.startIndexInclusive(), range.endIndexExclusive(), true);
    }

    private static int distanceFrom(Range range, int start) {
        return Math.abs(start - range.startIndexInclusive());
    }

    private IntStream occurrences(byte[] needle) {
        return IntStream.rangeClosed(0, to.length - needle.length)
                .filter(start -> Arrays.equals(to, start, start + needle.length, needle, 0, needle.length));
    }
}
