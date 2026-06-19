package com.mcpscanner.ui;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Pure validator for user-supplied custom HTTP headers. Rejects reserved header
 * names, blank keys, and CR/LF/NUL control bytes that would enable header
 * injection. Operates on plain string maps so it carries no Swing or Montoya
 * dependency and is unit-testable in isolation.
 */
public final class HeaderValidator {

    private static final Set<String> RESERVED_HEADERS = Set.of(
            "authorization", "mcp-session-id", "content-type", "accept");

    public Map<String, String> validate(Map<String, String> rawHeaders) {
        Map<String, String> validated = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : rawHeaders.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue() == null ? "" : entry.getValue();
            rejectIfBlankOrUnsafe(key, value);
            validated.put(key, value);
        }
        return validated;
    }

    private static void rejectIfBlankOrUnsafe(String key, String value) {
        if (key == null || key.isBlank()) {
            throw new IllegalArgumentException("Header name must not be empty or whitespace");
        }
        if (RESERVED_HEADERS.contains(key.toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException(
                    "Header name '" + key + "' is reserved and cannot be set as a custom header");
        }
        if (containsControlBytes(key)) {
            throw new IllegalArgumentException(
                    "Header name '" + key + "' contains illegal control characters (CR, LF, or NUL)");
        }
        if (containsControlBytes(value)) {
            throw new IllegalArgumentException(
                    "Header '" + key + "' value contains illegal control characters (CR, LF, or NUL)");
        }
    }

    private static boolean containsControlBytes(String text) {
        return text != null
                && (text.indexOf('\r') >= 0 || text.indexOf('\n') >= 0 || text.indexOf('\0') >= 0);
    }
}
