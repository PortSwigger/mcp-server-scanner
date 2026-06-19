package com.mcpscanner.checks;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public record AuthProbe(String label, Set<String> headersToRemove, Map<String, String> headersToOverride) {

    public AuthProbe {
        TreeSet<String> caseInsensitive = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        caseInsensitive.addAll(headersToRemove);
        headersToRemove = Collections.unmodifiableSortedSet(caseInsensitive);
        headersToOverride = Map.copyOf(headersToOverride);
    }
}
