package com.mcpscanner.http;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;

public interface OutsideBurpSends {

    void sentOutsideBurp(HttpRequestResponse exchange);

    default void streamRefused() {
    }

    static void reportRefusal(Http http) {
        if (http instanceof OutsideBurpSends observer) {
            observer.streamRefused();
        }
    }

    static void report(Http http, HttpRequestResponse exchange) {
        if (http instanceof OutsideBurpSends observer) {
            observer.sentOutsideBurp(exchange);
        }
    }
}
