package com.mcpscanner.checks.catalog.jwtvalidation;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;

record RefusalControls(HttpRequestResponse withoutCredential, HttpRequestResponse malformedBearer) {

    List<HttpRequestResponse> both() {
        return List.of(withoutCredential, malformedBearer);
    }
}
