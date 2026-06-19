package com.mcpscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;
import com.mcpscanner.mcp.McpRequestDetector;

import java.util.List;
import java.util.Locale;

/**
 * Distinguishes a FILESYSTEM not-found error from an ACCESS-DENIED / containment error in an MCP
 * {@code tools/call} or {@code resources/read} reply — the semantic differential the
 * CVE-2025-53110 prefix-sibling oracle keys on. Shared by both the tool-argument
 * ({@code ToolsCallTraversalProbeRunner}) and resource ({@code ResourcesReadProbeRunner}) runners.
 *
 * <p>Empirically grounded against the live {@code @modelcontextprotocol/server-filesystem} bridges
 * (vulnerable 2025.3.28 vs patched 2026.1.14) and the Python test-server prefix-match fixtures: for
 * a NON-EXISTENT path that lies outside the allowed root but shares its string prefix, the
 * vulnerable build passes its naive {@code startsWith(root)} containment check and then fails at
 * {@code open()} with a filesystem error ("Parent directory does not exist", "ENOENT: no such file
 * or directory"); the patched build rejects the path itself with "Access denied - path outside
 * allowed directories". A correctly-bounded server denies BEFORE touching the filesystem.
 *
 * <p>The not-found-vs-denied differential is only FP-safe when THIS server, through THIS injection
 * surface, is shown to produce a <em>distinguishable</em> denied response for an out-of-root path.
 * A server that masks every rejection as "file not found" would otherwise be falsely reported, so
 * the oracle requires a positive DENY-CONTROL (a clearly out-of-root, non-prefix-sharing path that
 * came back denied) alongside the not-found sibling. If the control is not a distinguishable deny
 * the oracle is blind and reports nothing — see {@link #prefixSiblingConfirmed}.
 *
 * <p>The patterns key on the SEMANTIC distinction (access/containment vs missing-file) rather than
 * any one server's exact wording, and access-denied always wins over not-found so a message that
 * mentions both ("access denied: ... no such file") is never misread as a not-found.
 */
final class FilesystemErrorOracle {

    private FilesystemErrorOracle() {}

    private static final List<String> ACCESS_DENIED_MARKERS = List.of(
            "access denied",
            "outside allowed directories",
            "outside the allowed",
            "not in allowed",
            "outside the resource root",
            "outside the root",
            "outside root",
            "not permitted",
            "permission denied",
            "not allowed",
            "forbidden",
            "escapes the",
            "is outside"
    );

    private static final List<String> NOT_FOUND_MARKERS = List.of(
            "enoent",
            "no such file",
            "no such file or directory",
            "parent directory does not exist",
            "does not exist",
            "cannot find",
            "not found",
            "file not found"
    );

    /**
     * Confirms a CVE-2025-53110 prefix-sibling boundary bypass for ONE injection surface.
     *
     * @param denyControl the reply for a clearly out-of-root, NON-prefix-sharing path sent through
     *                    the same surface — establishes the server emits a distinguishable deny
     * @param sibling     the reply for a NON-EXISTENT path that shares the root's string prefix
     * @return {@code true} only when the control is a distinguishable access-denied AND the sibling
     * is a filesystem not-found (not also denied). Any other combination — control not denied (the
     * oracle is blind), or sibling denied (the boundary held) — yields {@code false}, so a
     * not-found-masking server is skipped and a correctly-bounded server is never a false positive.
     */
    static boolean prefixSiblingConfirmed(HttpRequestResponse denyControl, HttpRequestResponse sibling) {
        return isAccessDenied(denyControl) && isNotFound(sibling);
    }

    /**
     * @return true when the response is an access-denied / containment rejection — used to confirm
     * the deny-control and to recognise the leaked-root error a root can be parsed from.
     */
    static boolean isAccessDenied(HttpRequestResponse response) {
        return containsAny(joinedLowerCaseText(response), ACCESS_DENIED_MARKERS);
    }

    /**
     * @return true when the response is a filesystem not-found error and is NOT an access-denied
     * error — i.e. the server reached the filesystem for a path it should have rejected. Access
     * denied wins so a message mentioning both markers is never misread as a not-found.
     */
    static boolean isNotFound(HttpRequestResponse response) {
        if (response.response() == null || response.response().statusCode() != 200) {
            return false;
        }
        // A success that returned content is not an error at all — handled by the signature oracle.
        if (McpRequestDetector.isToolCallSuccess(response)) {
            return false;
        }
        String message = joinedLowerCaseText(response);
        if (message.isBlank() || containsAny(message, ACCESS_DENIED_MARKERS)) {
            return false;
        }
        return containsAny(message, NOT_FOUND_MARKERS);
    }

    private static String joinedLowerCaseText(HttpRequestResponse response) {
        return String.join(" \n ", ToolCallTextExtractor.allTextFromResponse(response))
                .toLowerCase(Locale.ROOT);
    }

    private static boolean containsAny(String haystack, List<String> needles) {
        for (String needle : needles) {
            if (haystack.contains(needle)) {
                return true;
            }
        }
        return false;
    }
}
