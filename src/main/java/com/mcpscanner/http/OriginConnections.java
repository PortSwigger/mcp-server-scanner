package com.mcpscanner.http;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

final class OriginConnections {

    private final ConcurrentMap<Origin, OriginConnection> learned = new ConcurrentHashMap<>();

    OriginConnection of(HttpService service) {
        return learned.getOrDefault(Origin.of(service), OriginConnection.UNKNOWN);
    }

    static String originOf(HttpService service) {
        Origin origin = Origin.of(service);
        return (origin.secure() ? "https://" : "http://") + origin.host() + ":" + origin.port();
    }

    void learn(HttpService service, HttpResponse response) {
        OriginConnection.answeredWith(response.httpVersion())
                .ifPresent(connection -> learned.putIfAbsent(Origin.of(service), connection));
    }

    void reuseFailed(HttpService service) {
        learned.put(Origin.of(service), OriginConnection.CLOSING);
    }

    void forget() {
        learned.clear();
    }

    private record Origin(boolean secure, String host, int port) {

        static Origin of(HttpService service) {
            return new Origin(service.secure(), service.host().toLowerCase(Locale.ROOT), service.port());
        }
    }
}
