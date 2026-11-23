package com.mcpscanner.auth.oauth;

import java.util.List;
import java.util.Set;

public record ScopeSelection(Set<String> declined, List<String> customTicked) {

    private static final ScopeSelection NONE = new ScopeSelection(Set.of(), List.of());

    public ScopeSelection {
        declined = declined != null ? Set.copyOf(declined) : Set.of();
        customTicked = customTicked != null ? List.copyOf(customTicked) : List.of();
    }

    public static ScopeSelection none() {
        return NONE;
    }
}
