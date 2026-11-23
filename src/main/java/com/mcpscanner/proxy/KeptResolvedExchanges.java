package com.mcpscanner.proxy;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class KeptResolvedExchanges {

    private final int maxExchanges;
    private final Map<String, List<HttpRequestResponse>> leastRecentlyUsedFirst;

    KeptResolvedExchanges(int maxExchanges) {
        this.maxExchanges = maxExchanges;
        this.leastRecentlyUsedFirst = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, List<HttpRequestResponse>> eldest) {
                return size() > KeptResolvedExchanges.this.maxExchanges;
            }
        };
    }

    synchronized void keep(String id, List<HttpRequestResponse> items) {
        leastRecentlyUsedFirst.put(id, List.copyOf(items));
    }

    synchronized List<HttpRequestResponse> of(String id) {
        return leastRecentlyUsedFirst.getOrDefault(id, List.of());
    }
}
