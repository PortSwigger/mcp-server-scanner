package com.mcpscanner.scan;

import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

final class StringPlaceholder {

    static final String PLAIN = "test";
    private static final String HARMLESS_SQL = "SELECT 1";
    private static final String SQL_NAME_MARKER = "sql";
    // Exists on POSIX servers, so a tool validating the directory proceeds; it is shared scratch space.
    // A base call to a tool that may write is sent only after the user confirms (DestructiveScanGate).
    // "." is the server's application root and must never be used.
    private static final String SHARED_SCRATCH_DIRECTORY = "/tmp";
    private static final Set<String> DIRECTORY_NAMES = Set.of("dir", "folder", "cwd");
    private static final String DIRECTORY_NAME_MARKER = "directory";
    private static final String ABSOLUTE_URL = "https://example.com/";
    private static final Pattern URL_NAME = Pattern.compile(
            "(?i:^(url|uri)$)|(?i:[_-](url|uri)$)|[a-z](Url|URL|Uri|URI)$");
    private static final Map<String, String> BY_FORMAT = Map.ofEntries(
            Map.entry("email", "test@example.com"),
            Map.entry("idn-email", "test@example.com"),
            Map.entry("uri", "https://example.com/"),
            Map.entry("url", "https://example.com/"),
            Map.entry("iri", "https://example.com/"),
            Map.entry("uri-reference", "https://example.com/"),
            Map.entry("uuid", "00000000-0000-4000-8000-000000000001"),
            Map.entry("date-time", "2024-01-01T00:00:00Z"),
            Map.entry("date", "2024-01-01"),
            Map.entry("time", "00:00:00Z"),
            Map.entry("hostname", "example.com"),
            Map.entry("ipv4", "192.0.2.1"),
            Map.entry("ipv6", "2001:db8::1"));

    private StringPlaceholder() {
    }

    static String forProperty(String name, Map<String, Object> schema) {
        String format = BY_FORMAT.get(String.valueOf(schema.get("format")).toLowerCase(Locale.ROOT));
        if (format != null) {
            return format;
        }
        return fitted(unformatted(name), schema);
    }

    private static String unformatted(String name) {
        if (namesSql(name)) {
            return HARMLESS_SQL;
        }
        if (namesDirectory(name)) {
            return SHARED_SCRATCH_DIRECTORY;
        }
        return namesUrl(name) ? ABSOLUTE_URL : PLAIN;
    }

    private static boolean namesUrl(String name) {
        return name != null && URL_NAME.matcher(name).find();
    }

    private static boolean namesDirectory(String name) {
        if (name == null) {
            return false;
        }
        String lowered = name.toLowerCase(Locale.ROOT);
        return lowered.contains(DIRECTORY_NAME_MARKER) || DIRECTORY_NAMES.stream().anyMatch(
                marker -> lowered.equals(marker) || lowered.endsWith("_" + marker));
    }

    private static boolean namesSql(String name) {
        return name != null && name.toLowerCase(Locale.ROOT).contains(SQL_NAME_MARKER);
    }

    private static String fitted(String value, Map<String, Object> schema) {
        String padded = padded(value, length(schema.get("minLength"), 0));
        int maxLength = length(schema.get("maxLength"), Integer.MAX_VALUE);
        return padded.length() > maxLength ? padded.substring(0, Math.max(maxLength, 1)) : padded;
    }

    private static String padded(String value, int minLength) {
        if (minLength <= value.length()) {
            return value;
        }
        return PLAIN.repeat(minLength / PLAIN.length() + 1).substring(0, minLength);
    }

    private static int length(Object value, int fallback) {
        return value instanceof Number number ? number.intValue() : fallback;
    }
}
