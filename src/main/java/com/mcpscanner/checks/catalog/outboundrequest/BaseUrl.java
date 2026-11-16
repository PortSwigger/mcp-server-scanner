package com.mcpscanner.checks.catalog.outboundrequest;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Optional;

record BaseUrl(String scheme, String host, String remainder) {

    static Optional<BaseUrl> parse(String value) {
        try {
            URI uri = new URI(value.strip());
            return Optional.of(uri).filter(BaseUrl::isWebUrl).map(BaseUrl::of);
        } catch (URISyntaxException notAUrl) {
            return Optional.empty();
        }
    }

    String withHostSuffix(String suffix) {
        return scheme + "://" + host + "." + suffix + remainder;
    }

    String withUserInfoHost(String attackerHost) {
        return scheme + "://" + host + "@" + attackerHost + remainder;
    }

    private static boolean isWebUrl(URI uri) {
        String scheme = uri.getScheme();
        return uri.getHost() != null && ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme));
    }

    private static BaseUrl of(URI uri) {
        String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        String query = uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery();
        return new BaseUrl(uri.getScheme().toLowerCase(Locale.ROOT), uri.getHost(), path + query);
    }
}
