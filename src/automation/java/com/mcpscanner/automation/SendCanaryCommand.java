package com.mcpscanner.automation;

import java.net.URI;
import java.util.Set;

public record SendCanaryCommand(String url, int count, int concurrency) {

    public static final int MAX_COUNT = 10_000;
    public static final int MAX_CONCURRENCY = 64;

    private static final Set<String> WEB_SCHEMES = Set.of("http", "https");

    public SendCanaryCommand {
        if (url == null || !WEB_SCHEMES.contains(String.valueOf(URI.create(url).getScheme()))) {
            throw new IllegalArgumentException("url must be an http(s) URL, got " + url);
        }
        requireWithin("count", count, MAX_COUNT);
        requireWithin("concurrency", concurrency, MAX_CONCURRENCY);
    }

    private static void requireWithin(String name, int value, int max) {
        if (value < 1 || value > max) {
            throw new IllegalArgumentException(name + " must be 1.." + max + ", got " + value);
        }
    }
}
