package com.mcpscanner.access.listing;

import com.mcpscanner.checks.api.Principal;

import java.util.Collection;
import java.util.Collections;
import java.util.SortedSet;
import java.util.TreeSet;

record ToolList(Principal principal, SortedSet<String> tools) {

    ToolList(Principal principal, Collection<String> tools) {
        this(principal, Collections.unmodifiableSortedSet(new TreeSet<>(tools)));
    }

    SortedSet<String> beyond(Collection<String> others) {
        SortedSet<String> beyond = new TreeSet<>(tools);
        beyond.removeAll(others);
        return beyond;
    }

    boolean strictlyExceeds(ToolList other) {
        return !other.tools.isEmpty() && tools.containsAll(other.tools) && tools.size() > other.tools.size();
    }

    boolean within(ToolList other) {
        return other.tools.containsAll(tools);
    }

    String id() {
        return principal.id();
    }
}
