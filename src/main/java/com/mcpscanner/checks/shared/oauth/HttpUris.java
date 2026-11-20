package com.mcpscanner.checks.shared.oauth;

import com.mcpscanner.mcp.HttpOrigin;
import com.mcpscanner.mcp.LoopbackHosts;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

public final class HttpUris {

    private HttpUris() {
    }

    public static Optional<URI> parse(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        try {
            URI uri = new URI(value.trim());
            return isHttp(uri) && uri.getHost() != null && uri.getRawUserInfo() == null
                    ? Optional.of(uri) : Optional.empty();
        } catch (URISyntaxException malformed) {
            return Optional.empty();
        }
    }

    public static Optional<URI> resolve(URI base, String reference) {
        try {
            return parse(base.resolve(new URI(reference.trim())).toString());
        } catch (URISyntaxException | IllegalArgumentException malformed) {
            return Optional.empty();
        }
    }

    public static String origin(URI uri) {
        return HttpOrigin.of(uri).baseUrl();
    }

    public static boolean sameOrigin(URI left, URI right) {
        return HttpOrigin.sameOrigin(left, right);
    }

    public static String withoutQuery(URI uri) {
        return origin(uri) + (uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath());
    }

    public static String pathWithoutTrailingSlash(URI uri) {
        String path = uri.getRawPath() == null ? "" : uri.getRawPath();
        return path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
    }

    public static boolean isSecureOrLoopback(URI uri) {
        return "https".equalsIgnoreCase(uri.getScheme()) || LoopbackHosts.isLoopback(uri.getHost());
    }

    private static boolean isHttp(URI uri) {
        String scheme = uri.getScheme();
        return "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
    }
}
