package com.mcpscanner.checks;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Per-host dedup helper shared by checks that must only run their probe sequence
 * once per target.
 *
 * <p>The base identity is the {@code scheme://host:port} triple alone. Auth-independent
 * probes (DCR, consent-page reflection) exercise the authorization server's own
 * registration and consent surfaces, which behave the same regardless of which bearer
 * the MCP session happens to carry — a rotated bearer is NOT a fresh target, so those
 * callers use {@link #tryClaim(HttpRequest)} / {@link #releaseIfHttpLayerErrored(HttpRequest)}.
 * Including the bearer in the key let the scan-start baseline (which keeps Authorization)
 * and the on-wire scan request (which strips it) diverge into two keys and report the same
 * finding twice.
 *
 * <p>Checks whose result genuinely depends on the supplied credentials (auth-bypass,
 * hidden-method enumeration) opt into per-credential re-probing via the
 * {@code identityDiscriminator} overloads — a different bearer then counts as a fresh
 * target.
 *
 * <p>Claim is atomic — {@code tryClaim} returns {@code true} iff this call inserted the
 * key. Concurrent invocations across worker threads cannot all see "not claimed" and emit
 * duplicate findings.
 *
 * <p>{@code releaseIfHttpLayerErrored} reverses a prior claim so a subsequent invocation
 * can re-probe; callers should release when probes failed at the HTTP layer: a pure
 * HTTP-layer failure shouldn't poison the dedup set, a retry might succeed.
 */
public final class HostDedup {

    private final Set<String> claimedHosts = ConcurrentHashMap.newKeySet();

    public boolean tryClaim(HttpRequest request) {
        return claimedHosts.add(hostKey(request));
    }

    public boolean tryClaim(HttpRequest request, String identityDiscriminator) {
        return claimedHosts.add(keyWithIdentity(request, identityDiscriminator));
    }

    /** Drops every claim so a reconnect re-probes each host from scratch. */
    public void clear() {
        claimedHosts.clear();
    }

    public void releaseIfHttpLayerErrored(HttpRequest request) {
        claimedHosts.remove(hostKey(request));
    }

    public void releaseIfHttpLayerErrored(HttpRequest request, String identityDiscriminator) {
        claimedHosts.remove(keyWithIdentity(request, identityDiscriminator));
    }

    /**
     * @return a fingerprint of the Authorization, Cookie, and Mcp-Session-Id headers,
     * for callers whose probe result depends on the supplied credentials.
     */
    public static String authFingerprint(HttpRequest request) {
        Set<String> identityHeaders = Set.of("Authorization", "Cookie", "Mcp-Session-Id");
        return request.headers().stream()
                .filter(header -> identityHeaders.stream()
                        .anyMatch(known -> known.equalsIgnoreCase(header.name())))
                .map(header -> header.name().toLowerCase() + "="
                        + Integer.toHexString(header.value().hashCode()))
                .sorted()
                .collect(Collectors.joining(";"));
    }

    private static String keyWithIdentity(HttpRequest request, String identityDiscriminator) {
        return hostKey(request) + "|" + identityDiscriminator;
    }

    private static String hostKey(HttpRequest request) {
        HttpService service = request.httpService();
        String scheme = service.secure() ? "https" : "http";
        return scheme + "://" + service.host() + ":" + service.port();
    }
}
