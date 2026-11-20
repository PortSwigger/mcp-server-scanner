package com.mcpscanner.mcp;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

public record FramedOperation(Map<String, String> headers) {

    public static final List<String> RECORDED_HEADERS = List.of(McpHeaders.METHOD, McpHeaders.NAME,
            McpHeaders.PROTOCOL_VERSION);

    private static final String SEPARATOR = "\n";

    public FramedOperation {
        Map<String, String> lowerCased = new HashMap<>();
        headers.forEach((name, value) -> lowerCased.put(name.toLowerCase(Locale.ROOT), value));
        headers = Map.copyOf(lowerCased);
    }

    public static boolean records(String headerName) {
        return RECORDED_HEADERS.stream().anyMatch(headerName::equalsIgnoreCase);
    }

    public static String encode(Map<String, String> framedHeaders) {
        StringBuilder record = new StringBuilder();
        framedHeaders.forEach((name, value) -> {
            if (records(name)) {
                record.append(name.toLowerCase(Locale.ROOT)).append(SEPARATOR).append(value).append(SEPARATOR);
            }
        });
        return Base64.getUrlEncoder().withoutPadding().encodeToString(record.toString().getBytes(StandardCharsets.UTF_8));
    }

    public static Optional<FramedOperation> decode(String recorded) {
        if (recorded == null) {
            return Optional.empty();
        }
        try {
            String[] parts = new String(Base64.getUrlDecoder().decode(recorded), StandardCharsets.UTF_8)
                    .split(SEPARATOR, -1);
            Map<String, String> headers = new HashMap<>();
            for (int i = 0; i + 1 < parts.length; i += 2) {
                headers.put(parts[i], parts[i + 1]);
            }
            return Optional.of(new FramedOperation(headers));
        } catch (IllegalArgumentException unreadable) {
            return Optional.empty();
        }
    }

    public boolean framed(String headerName, String value) {
        return value.equals(headers.get(headerName.toLowerCase(Locale.ROOT)));
    }
}
