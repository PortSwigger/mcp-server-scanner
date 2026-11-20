package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Optional;

record Redemption(Optional<String> accessToken, Optional<String> refreshToken,
                  Optional<HttpRequestResponse> exchange, Optional<String> scope) {

    static Redemption unanswered() {
        return new Redemption(Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
    }

    String status() {
        return exchange.map(answered -> "HTTP " + answered.response().statusCode()).orElse("no answer");
    }
}
