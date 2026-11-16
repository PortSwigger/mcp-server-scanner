package com.mcpscanner.checks.catalog.sqlinjection;

import burp.api.montoya.http.message.HttpRequestResponse;

record Probe(HttpRequestResponse exchange, ReplyShape shape) {
}
