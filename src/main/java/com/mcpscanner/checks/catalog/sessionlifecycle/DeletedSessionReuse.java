package com.mcpscanner.checks.catalog.sessionlifecycle;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.Optional;

record DeletedSessionReuse(HttpRequestResponse unissuedIdRefused, HttpRequestResponse delete,
                           Optional<HttpRequestResponse> answeredAfter,
                           Optional<StreamReuse> streamAfter) {
}
