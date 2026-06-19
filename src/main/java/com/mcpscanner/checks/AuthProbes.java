package com.mcpscanner.checks;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.mcpscanner.auth.AuthHeaderNames;
import com.mcpscanner.auth.AuthStrategy;
import com.mcpscanner.mcp.ScannerSentinels;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

public final class AuthProbes {

    /**
     * Appended to auth-bypass / unauthenticated-discovery findings only when the active transport
     * is SSE. On the SSE path Burp's requests flow through the local proxy, which deliberately
     * preserves Mcp-Session-Id (it is in NON_AUTH_SESSION_HEADERS) so the upstream event-stream
     * stays alive — even when the probe carries the strip-auth sentinel. The Authorization strip
     * is genuine, but the session id is re-injected, so the finding demonstrates "auth not enforced
     * given an initialized session" rather than "no identity at all". On Streamable HTTP, Burp
     * sends directly with no proxy, so the strip is complete and this caveat does not apply.
     */
    public static final String SSE_SESSION_CAVEAT =
            "Transport caveat (SSE): on the SSE transport the scanner's local proxy preserves the "
                    + "Mcp-Session-Id header to keep the upstream event stream alive, so this probe "
                    + "still carried an initialized session id even though the Authorization header "
                    + "was stripped. The finding therefore demonstrates that authentication is not "
                    + "enforced given an already-initialized session, not that the server grants "
                    + "access with no identity at all. Verify manually whether the server treats the "
                    + "session id alone as proof of authentication.";

    /**
     * Appended to the auth-bypass finding on every transport. The scanner's local proxy fronts all
     * scanner-issued requests and re-injects Mcp-Session-Id (it is in
     * {@code SseProxyServer.NON_AUTH_SESSION_HEADERS}) on both Streamable HTTP and SSE, so the
     * strip-auth probe always reaches the server with a valid post-initialize session even though
     * the Authorization header was genuinely stripped. A positive therefore proves the server does
     * not re-validate the bearer per request — it trusts the session id — rather than fully
     * anonymous access. Exploitability depends on whether the session id can be obtained or
     * predicted by an attacker who lacks the bearer token.
     */
    public static final String SESSION_TRUST_CAVEAT =
            "Session-trust caveat: the scanner's local proxy re-injects the Mcp-Session-Id header on "
                    + "every probe, so this request still carried a valid post-initialize session id "
                    + "even though the Authorization header was stripped. The finding therefore "
                    + "demonstrates that the server does not re-validate the bearer token on every "
                    + "request — it trusts the session id — rather than that it grants access with no "
                    + "identity at all. Exploitability depends on whether an attacker who lacks the "
                    + "bearer token can obtain or predict a valid Mcp-Session-Id.";

    private static final String AUTHORIZATION = "Authorization";
    private static final String COOKIE = "Cookie";
    private static final String MCP_SESSION_ID = "Mcp-Session-Id";

    private static final String EMPTY_BEARER_VALUE = "Bearer ";
    private static final String GARBAGE_TOKEN = "not_a_real_token_12345";
    private static final String GARBAGE_BEARER_VALUE = "Bearer " + GARBAGE_TOKEN;
    private static final String GARBAGE_CUSTOM_HEADER_VALUE = "not_a_real_credential_12345";

    private AuthProbes() {}

    // Every auth-bypass probe attaches the strip sentinel via ScannerSentinels so SseProxyServer
    // suppresses the session's stored Authorization/Cookie/custom-auth headers before forwarding
    // upstream. Without it the proxy would re-inject those headers and silently mask the probe.
    public static AuthProbe stripAuth(AuthStrategy authStrategy) {
        return new AuthProbe("STRIP_AUTH", identityCarryingHeaderNames(authStrategy),
                ScannerSentinels.stripAuthOnly());
    }

    public static List<AuthProbe> invalidTokenProbes(AuthStrategy authStrategy) {
        Set<String> headersToRemove = identityCarryingHeaderNames(authStrategy);
        List<AuthProbe> probes = new ArrayList<>();
        // Bearer probes fire for every strategy (including custom-header) as defence-in-depth:
        // some servers wrongly honour an attacker-supplied Authorization header even when none was configured.
        probes.add(new AuthProbe("EMPTY_BEARER", headersToRemove,
                ScannerSentinels.withStripAuth(AUTHORIZATION, EMPTY_BEARER_VALUE)));
        probes.add(new AuthProbe("GARBAGE_BEARER", headersToRemove,
                ScannerSentinels.withStripAuth(AUTHORIZATION, GARBAGE_BEARER_VALUE)));
        probes.add(new AuthProbe("NO_SCHEME", headersToRemove,
                ScannerSentinels.withStripAuth(AUTHORIZATION, GARBAGE_TOKEN)));
        for (String customHeader : customAuthHeaderNames(authStrategy)) {
            String label = customHeader.toUpperCase(Locale.ROOT);
            probes.add(new AuthProbe("EMPTY_" + label, headersToRemove,
                    ScannerSentinels.withStripAuth(customHeader, "")));
            probes.add(new AuthProbe("GARBAGE_" + label, headersToRemove,
                    ScannerSentinels.withStripAuth(customHeader, GARBAGE_CUSTOM_HEADER_VALUE)));
        }
        return List.copyOf(probes);
    }

    /**
     * Auth-credential headers (Authorization, Cookie, contributed custom-auth) — strip these to
     * send a request as if the operator's credentials were not configured. Preserves
     * Mcp-Session-Id so session-bound servers can still respond on the existing session.
     * Mcp-Session-Id is deliberately excluded because session state is a transport concern, not
     * a credential — probes can keep the session intact while stripping the credential.
     */
    public static Set<String> authBearingHeaderNames(AuthStrategy authStrategy) {
        return AuthHeaderNames.authBearingHeaderNames(authStrategy);
    }

    public static boolean hasAuthBearingHeaders(HttpRequest request, AuthStrategy authStrategy) {
        Set<String> gateNames = authBearingHeaderNames(authStrategy);
        return request.headers().stream().anyMatch(header -> gateNames.contains(header.name()));
    }

    /**
     * Auth-bearing headers PLUS Mcp-Session-Id — strip these to probe whether the server allows
     * access without ANY pre-existing identity / session. Used by auth-bypass and tool-enum
     * probes that simulate an unauthenticated client.
     */
    public static Set<String> identityCarryingHeaderNames(AuthStrategy authStrategy) {
        Set<String> names = authBearingHeaderNames(authStrategy);
        names.add(MCP_SESSION_ID);
        return names;
    }

    private static List<String> customAuthHeaderNames(AuthStrategy authStrategy) {
        return authStrategy.contributedHeaderNames().stream()
                .filter(h -> !AUTHORIZATION.equalsIgnoreCase(h) && !COOKIE.equalsIgnoreCase(h))
                .toList();
    }

    /**
     * Renders a probe's internal label as a plain-English credential condition for issue text,
     * so findings read "no Authorization header" rather than the {@code STRIP_AUTH} enum name.
     * Custom-header probes recover the original header casing from the override map.
     */
    public static String describe(AuthProbe probe) {
        String label = probe.label();
        return switch (label) {
            case "STRIP_AUTH" -> "no Authorization header";
            case "EMPTY_BEARER" -> "empty bearer token";
            case "GARBAGE_BEARER" -> "invalid bearer token";
            case "NO_SCHEME" -> "token with no scheme";
            default -> describeCustomHeaderProbe(label, probe);
        };
    }

    private static String describeCustomHeaderProbe(String label, AuthProbe probe) {
        String headerName = customHeaderName(probe);
        if (label.startsWith("EMPTY_")) {
            return "empty " + headerName + " header";
        }
        if (label.startsWith("GARBAGE_")) {
            return "invalid " + headerName + " header";
        }
        return label;
    }

    private static String customHeaderName(AuthProbe probe) {
        return probe.headersToOverride().keySet().stream()
                .filter(name -> !AUTHORIZATION.equalsIgnoreCase(name)
                        && !name.regionMatches(true, 0, "X-Mcp-Scanner-", 0, "X-Mcp-Scanner-".length()))
                .findFirst()
                .orElse("custom-auth");
    }
}
