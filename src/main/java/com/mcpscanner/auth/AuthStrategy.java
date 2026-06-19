package com.mcpscanner.auth;

import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public interface AuthStrategy {

    Map<String, String> headers();

    default Set<String> contributedHeaderNames() {
        Set<String> names = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        names.addAll(headers().keySet());
        return names;
    }

    default boolean supportsRefresh() {
        return false;
    }

    default boolean refresh() {
        return false;
    }

    default boolean isTerminallyFailed() {
        return false;
    }
}
