package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.http.message.HttpRequestResponse;

record CorsEvidence(String name, HttpRequestResponse exchange, boolean outsideBurp) {

    String grantSummary() {
        return name + ": " + CorsGrant.of(exchange).describe();
    }
}
