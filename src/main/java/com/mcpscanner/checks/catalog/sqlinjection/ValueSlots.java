package com.mcpscanner.checks.catalog.sqlinjection;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class ValueSlots {

    private static final Pattern URI_SCHEME = Pattern.compile("^[A-Za-z][A-Za-z0-9+.-]*://");
    private static final int MAX_SEGMENTS = 4;

    private ValueSlots() {
    }

    static List<ValueSlot> of(String value) {
        List<ValueSlot> slots = new ArrayList<>();
        slots.add(ValueSlot.whole(value));
        Matcher scheme = URI_SCHEME.matcher(value);
        if (scheme.find()) {
            slots.addAll(segments(value, scheme.end()));
        }
        return List.copyOf(slots);
    }

    private static List<ValueSlot> segments(String value, int start) {
        List<ValueSlot> segments = new ArrayList<>();
        int end = pathEnd(value, start);
        int cursor = start;
        while (cursor < end && segments.size() < MAX_SEGMENTS) {
            int next = nextDelimiter(value, cursor, end);
            if (next > cursor) {
                segments.add(new ValueSlot(value.substring(0, cursor), value.substring(cursor, next),
                        value.substring(next)));
            }
            cursor = next + 1;
        }
        return segments;
    }

    private static int pathEnd(String value, int start) {
        for (int index = start; index < value.length(); index++) {
            if (value.charAt(index) == '?' || value.charAt(index) == '#') {
                return index;
            }
        }
        return value.length();
    }

    private static int nextDelimiter(String value, int from, int end) {
        for (int index = from; index < end; index++) {
            if (ValueSlot.DELIMITERS.indexOf(value.charAt(index)) >= 0) {
                return index;
            }
        }
        return end;
    }
}
