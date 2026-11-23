package com.mcpscanner.checks.shared.oauth;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URI;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

final class CookieJar {

    private final List<SessionCookie> initial;
    private final Map<String, String> collected = new LinkedHashMap<>();

    CookieJar(List<SessionCookie> initial) {
        this.initial = initial.stream()
                .sorted(Comparator.comparingInt((SessionCookie cookie) -> cookie.path().length()).reversed())
                .toList();
    }

    void collect(HttpResponse response) {
        ResponseHeaders.values(response, "Set-Cookie").stream()
                .map(header -> header.split(";", 2)[0].trim())
                .filter(pair -> pair.indexOf('=') > 0)
                .forEach(pair -> collected.put(pair.substring(0, pair.indexOf('=')), pair.substring(pair.indexOf('=') + 1)));
    }

    Map<String, String> header(URI target) {
        Map<String, String> cookies = initialAt(target.getRawPath());
        cookies.putAll(collected);
        if (cookies.isEmpty()) {
            return Map.of();
        }
        return Map.of("Cookie", cookies.entrySet().stream()
                .map(cookie -> cookie.getKey() + "=" + cookie.getValue())
                .collect(Collectors.joining("; ")));
    }

    private Map<String, String> initialAt(String path) {
        Map<String, String> cookies = new LinkedHashMap<>();
        initial.stream()
                .filter(cookie -> CookiePath.admits(cookie.path(), path))
                .forEach(cookie -> cookies.putIfAbsent(cookie.name(), cookie.value()));
        return cookies;
    }
}
