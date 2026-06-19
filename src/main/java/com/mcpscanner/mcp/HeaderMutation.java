package com.mcpscanner.mcp;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public final class HeaderMutation {

    private HeaderMutation() {}

    public static HttpRequest apply(HttpRequest baseline,
                                    Collection<String> headersToRemove,
                                    Map<String, String> headersToOverride) {
        HttpRequest current = removeHeaders(baseline, headersToRemove);
        for (Map.Entry<String, String> override : headersToOverride.entrySet()) {
            current = current.withHeader(override.getKey(), override.getValue());
        }
        return current;
    }

    private static HttpRequest removeHeaders(HttpRequest request, Collection<String> namesToRemove) {
        if (namesToRemove.isEmpty()) {
            return request;
        }
        List<HttpHeader> matching = request.headers().stream()
                .filter(header -> containsIgnoreCase(namesToRemove, header.name()))
                .toList();
        return matching.isEmpty() ? request : request.withRemovedHeaders(matching);
    }

    private static boolean containsIgnoreCase(Collection<String> names, String candidate) {
        for (String name : names) {
            if (name.equalsIgnoreCase(candidate)) {
                return true;
            }
        }
        return false;
    }
}
