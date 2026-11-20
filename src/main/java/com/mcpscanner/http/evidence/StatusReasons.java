package com.mcpscanner.http.evidence;

import java.util.Map;

public final class StatusReasons {

    private static final Map<Integer, String> REASONS = Map.ofEntries(
            Map.entry(200, "OK"), Map.entry(201, "Created"), Map.entry(202, "Accepted"),
            Map.entry(204, "No Content"), Map.entry(301, "Moved Permanently"), Map.entry(302, "Found"),
            Map.entry(303, "See Other"), Map.entry(307, "Temporary Redirect"), Map.entry(308, "Permanent Redirect"),
            Map.entry(400, "Bad Request"), Map.entry(401, "Unauthorized"), Map.entry(403, "Forbidden"),
            Map.entry(404, "Not Found"), Map.entry(405, "Method Not Allowed"), Map.entry(406, "Not Acceptable"),
            Map.entry(408, "Request Timeout"), Map.entry(409, "Conflict"), Map.entry(421, "Misdirected Request"),
            Map.entry(425, "Too Early"), Map.entry(429, "Too Many Requests"),
            Map.entry(500, "Internal Server Error"), Map.entry(502, "Bad Gateway"),
            Map.entry(503, "Service Unavailable"), Map.entry(504, "Gateway Timeout"));

    private StatusReasons() {
    }

    public static String of(int status) {
        return REASONS.getOrDefault(status, "");
    }
}
