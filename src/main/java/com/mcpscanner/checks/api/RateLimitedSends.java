package com.mcpscanner.checks.api;

import burp.api.montoya.http.Http;

public record RateLimitedSends(Http probes, Http confirmations) {
}
