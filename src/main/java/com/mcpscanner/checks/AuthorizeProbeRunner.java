package com.mcpscanner.checks;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Drives a single OAuth authorization-code {@code GET /authorize} request and reports the raw
 * outcome (status, {@code Location}, body) for a caller to classify. Each call mints a fresh
 * PKCE verifier/challenge (S256) and a random {@code state}; redirects are NOT followed so the
 * caller inspects the first response. Deliberately decoupled from any one check so it can be
 * reused (e.g. to fetch an OAuth consent page).
 */
public final class AuthorizeProbeRunner {

    private static final String ACCEPT_HEADER = "Accept";
    private static final String TEXT_HTML = "text/html";
    private static final String LOCATION_HEADER = "Location";

    public record AuthorizeResult(boolean reachedServer,
                                  int statusCode,
                                  String location,
                                  String body,
                                  HttpRequestResponse exchange) {
    }

    public record FetchResult(boolean fetched, String body, HttpRequestResponse exchange) {
        static FetchResult notFetched() {
            return new FetchResult(false, null, null);
        }
    }

    private final Http http;
    private final SecureRandom random = new SecureRandom();

    public AuthorizeProbeRunner(Http http) {
        this.http = http;
    }

    public AuthorizeResult send(AuthorizeProbe probe) {
        String verifier = randomToken();
        String challenge = pkceChallenge(verifier);
        String state = randomToken();
        HttpRequest request = HttpRequest.httpRequestFromUrl(buildUrl(probe, challenge, state))
                .withMethod("GET")
                .withAddedHeader(ACCEPT_HEADER, TEXT_HTML);
        HttpRequestResponse exchange = http.sendRequest(request);
        HttpResponse response = exchange.response();
        if (response == null) {
            return new AuthorizeResult(false, 0, null, null, exchange);
        }
        return new AuthorizeResult(true,
                response.statusCode(),
                response.headerValue(LOCATION_HEADER),
                response.bodyToString(),
                exchange);
    }

    /**
     * Follows a single same-origin hop from an {@code /authorize} response to fetch a rendered
     * consent page. The {@code locationOrPath} is resolved against {@code authorizeUrl}; the hop
     * is taken only when the resolved target shares scheme, host and port with {@code authorizeUrl}.
     * Cross-origin (broker) and scheme-downgrade targets are refused so no request leaves the
     * authorization origin. Bounded to one hop — the result is never followed further.
     */
    public FetchResult fetchSameOrigin(URI authorizeUrl, String locationOrPath) {
        if (locationOrPath == null || locationOrPath.isBlank()) {
            return FetchResult.notFetched();
        }
        URI resolved;
        try {
            resolved = authorizeUrl.resolve(locationOrPath.trim());
        } catch (IllegalArgumentException e) {
            return FetchResult.notFetched();
        }
        if (!isSameOrigin(authorizeUrl, resolved)) {
            return FetchResult.notFetched();
        }
        HttpRequest request = HttpRequest.httpRequestFromUrl(resolved.toString())
                .withMethod("GET")
                .withAddedHeader(ACCEPT_HEADER, TEXT_HTML);
        HttpRequestResponse exchange = http.sendRequest(request);
        HttpResponse response = exchange.response();
        if (response == null) {
            return FetchResult.notFetched();
        }
        return new FetchResult(true, response.bodyToString(), exchange);
    }

    private static boolean isSameOrigin(URI origin, URI candidate) {
        return matches(origin.getScheme(), candidate.getScheme())
                && matches(origin.getHost(), candidate.getHost())
                && effectivePort(origin) == effectivePort(candidate);
    }

    private static boolean matches(String a, String b) {
        return a != null && a.equalsIgnoreCase(b);
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    private static String buildUrl(AuthorizeProbe probe, String challenge, String state) {
        StringBuilder query = new StringBuilder()
                .append("response_type=code")
                .append("&client_id=").append(encode(probe.clientId()))
                .append("&redirect_uri=").append(encode(probe.redirectUri()))
                .append("&code_challenge=").append(encode(challenge))
                .append("&code_challenge_method=S256")
                .append("&state=").append(encode(state));
        if (probe.scope() != null && !probe.scope().isBlank()) {
            query.append("&scope=").append(encode(probe.scope()));
        }
        String endpoint = probe.authorizationEndpoint().toString();
        String separator = endpoint.contains("?") ? "&" : "?";
        return endpoint + separator + query;
    }

    private String randomToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String pkceChallenge(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable for PKCE challenge", e);
        }
    }

    private static String encode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
