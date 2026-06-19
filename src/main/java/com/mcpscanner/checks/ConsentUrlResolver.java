package com.mcpscanner.checks;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Pure helper that unwraps an OAuth consent URL embedded in a login/sign-in bounce.
 *
 * <p>Some authorization servers answer {@code GET /authorize} with a 3xx (or an HTML interstitial)
 * whose {@code Location} points CROSS-ORIGIN to a sign-in page, carrying the real same-origin consent
 * URL inside SOME query parameter (one known server uses {@code postSignUp}; others use {@code callback},
 * {@code goto}, {@code target_link_uri}, {@code returnTo}, {@code after_sign_in_url}, etc.). The
 * consent-page reflected-XSS check's same-origin one-hop refuses the cross-origin bounce and never
 * reaches the consent HTML; this resolver recovers the embedded consent URL from whichever query
 * parameter carries it — WITHOUT relying on a vendor-specific key allowlist.
 *
 * <p>Discovery is param-name-agnostic: every query-parameter value on the login bounce is
 * URL-decoded and the FIRST value that parses as an absolute URL whose ORIGIN exactly equals the AS
 * origin wins. A matched-but-non-consent AS-origin URL is harmless — the caller fetches it once and
 * simply finds no reflection.
 *
 * <p>CRITICAL SAFETY BOUND: the resolver only ever returns a candidate whose ORIGIN
 * (scheme + host + port) EXACTLY equals the discovered Authorization Server origin. Any candidate
 * that is cross-origin, a different host, a scheme downgrade, loopback, relative, or absent is
 * skipped. This keeps the check from becoming an SSRF / open-fetch primitive: the consent page lives
 * on the AS origin, so nothing else is ever worth fetching.
 *
 * <p>Deliberately decoupled from Burp/HTTP so the URL reasoning is unit-testable in isolation.
 */
public final class ConsentUrlResolver {

    /**
     * Returns the AS-origin consent URL embedded in an {@code /authorize} login bounce, or empty.
     *
     * @param location the {@code Location} header value (a sign-in/login URL carrying the consent URL)
     * @param asOrigin the discovered Authorization Server origin (host of the authorization endpoint)
     */
    public Optional<URI> resolve(String location, URI asOrigin) {
        if (location == null || location.isBlank() || asOrigin == null) {
            return Optional.empty();
        }
        URI loginUri = parse(location.trim());
        if (loginUri == null || loginUri.getRawQuery() == null) {
            return Optional.empty();
        }
        return firstAsOriginCandidate(loginUri.getRawQuery(), asOrigin);
    }

    private static Optional<URI> firstAsOriginCandidate(String rawQuery, URI asOrigin) {
        for (String value : queryValues(rawQuery)) {
            URI candidate = parse(decode(value));
            if (candidate != null && isExactlyOrigin(asOrigin, candidate)) {
                return Optional.of(candidate);
            }
        }
        return Optional.empty();
    }

    private static List<String> queryValues(String rawQuery) {
        List<String> values = new ArrayList<>();
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0 && eq < pair.length() - 1) {
                values.add(pair.substring(eq + 1));
            }
        }
        return values;
    }

    private static String decode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return value;
        }
    }

    private static URI parse(String value) {
        if (value == null) {
            return null;
        }
        try {
            return new URI(value);
        } catch (URISyntaxException e) {
            return null;
        }
    }

    private static boolean isExactlyOrigin(URI origin, URI candidate) {
        if (candidate == null || candidate.getHost() == null || candidate.getScheme() == null) {
            return false;
        }
        return equalsIgnoreCase(origin.getScheme(), candidate.getScheme())
                && equalsIgnoreCase(origin.getHost(), candidate.getHost())
                && effectivePort(origin) == effectivePort(candidate);
    }

    private static boolean equalsIgnoreCase(String a, String b) {
        return a != null && a.equalsIgnoreCase(b);
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }
}
