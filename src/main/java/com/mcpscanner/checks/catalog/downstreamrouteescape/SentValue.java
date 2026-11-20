package com.mcpscanner.checks.catalog.downstreamrouteescape;

import burp.api.montoya.http.message.HttpRequestResponse;

record SentValue(String value, HttpRequestResponse exchange) {
}
