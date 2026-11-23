package com.mcpscanner.automation;

import java.net.URI;
import java.util.Set;

final class WebUrls {

    private static final Set<String> WEB_SCHEMES = Set.of("http", "https");

    private WebUrls() {
    }

    static void requireWeb(String url) {
        if (url == null || !WEB_SCHEMES.contains(String.valueOf(URI.create(url).getScheme()))) {
            throw new IllegalArgumentException("url must be an http(s) URL, got " + url);
        }
    }
}
