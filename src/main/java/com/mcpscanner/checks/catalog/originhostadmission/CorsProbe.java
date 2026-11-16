package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.checks.shared.auth.CredentialHeaders;
import com.mcpscanner.mcp.HeaderMutation;
import com.mcpscanner.mcp.McpHeaders;
import com.mcpscanner.mcp.ScannerSentinels;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;

final class CorsProbe {

    static final String FOREIGN_ORIGIN = "http://evil.example";
    static final AdmissionProbe FOREIGN_ORIGIN_POST = new AdmissionProbe("Origin: " + FOREIGN_ORIGIN,
            AdmissionCategory.ORIGIN, Map.of("Origin", FOREIGN_ORIGIN));

    private static final String PREFLIGHT_METHOD = "OPTIONS";
    private static final String CONTENT_TYPE = "content-type";
    private static final String COOKIE = "cookie";
    private static final String HOST = "Host";
    private static final Set<String> SESSION_HEADERS = McpHeaders.caseInsensitive(McpHeaders.SESSION_ID,
            McpHeaders.PROTOCOL_VERSION);

    private final CredentialHeaders credentials;

    CorsProbe(CredentialHeaders credentials) {
        this.credentials = credentials;
    }

    HttpRequest preflightFor(HttpRequest delivered) {
        Map<String, String> preflight = new LinkedHashMap<>();
        preflight.put("Accept", "*/*");
        preflight.put("Origin", FOREIGN_ORIGIN);
        preflight.put("Access-Control-Request-Method", delivered.method());
        preflight.put("Access-Control-Request-Headers", String.join(",", requestedHeaders(delivered)));
        HttpRequest bare = delivered.withMethod(PREFLIGHT_METHOD).withBody("");
        return HeaderMutation.apply(bare, droppedHeaders(bare), preflight);
    }

    List<String> requestedHeaders(HttpRequest delivered) {
        Set<String> names = new TreeSet<>();
        names.add(CONTENT_TYPE);
        Stream.concat(delivered.headers().stream().map(HttpHeader::name).filter(SESSION_HEADERS::contains),
                        credentials.carriedNames(delivered).stream())
                .map(name -> name.toLowerCase(Locale.ROOT))
                .filter(name -> !name.equals(COOKIE))
                .forEach(names::add);
        return List.copyOf(names);
    }

    CorsAuth authOf(HttpRequest delivered) {
        return CorsAuth.of(credentials.carriedNames(delivered));
    }

    private static List<String> droppedHeaders(HttpRequest request) {
        return request.headers().stream().map(HttpHeader::name).filter(name -> !kept(name)).toList();
    }

    private static boolean kept(String name) {
        return HOST.equalsIgnoreCase(name) || ScannerSentinels.ALL.contains(name);
    }
}
