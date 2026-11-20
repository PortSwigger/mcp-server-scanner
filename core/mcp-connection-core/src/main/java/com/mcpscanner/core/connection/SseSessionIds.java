package com.mcpscanner.core.connection;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Set;

public final class SseSessionIds {
    private static final Set<String> PARAMETERS = Set.of("session_id", "sessionId");

    private SseSessionIds() {}

    public static Optional<String> from(String endpoint) {
        return sentFrom(endpoint).map(SseSessionIds::decode).filter(id -> !id.isEmpty());
    }

    public static Optional<String> sentFrom(String endpoint) {
        int query = endpoint.indexOf('?');
        if (query < 0) return Optional.empty();
        for (String pair : endpoint.substring(query + 1).split("&")) {
            int separator = pair.indexOf('=');
            if (separator > 0 && PARAMETERS.contains(pair.substring(0, separator)))
                return Optional.of(pair.substring(separator + 1)).filter(id -> !id.isEmpty());
        }
        return Optional.empty();
    }

    private static String decode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }
}
