package com.mcpscanner.checks.catalog.jwtvalidation;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Optional;

record AcceptedForgery(String description, HttpRequestResponse candidate,
                       Optional<HttpRequestResponse> refusedWrongKeyControl) {
}
