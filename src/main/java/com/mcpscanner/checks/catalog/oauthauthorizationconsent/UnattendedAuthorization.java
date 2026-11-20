package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.net.URI;
import java.util.List;
import java.util.Optional;

record UnattendedAuthorization(Optional<IssuedCode> code, List<HttpRequestResponse> exchanges,
                               Optional<URI> sessionCreatedBy, boolean hopLimitReached, Optional<URI> callback) {

    UnattendedAuthorization {
        exchanges = List.copyOf(exchanges);
    }

    static UnattendedAuthorization unanswered() {
        return new UnattendedAuthorization(Optional.empty(), List.of(), Optional.empty(), false,
                Optional.empty());
    }

    int redirectsFollowed() {
        return Math.max(0, exchanges.size() - 1);
    }
}
