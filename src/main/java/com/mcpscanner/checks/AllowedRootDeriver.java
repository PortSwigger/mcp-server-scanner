package com.mcpscanner.checks;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;
import java.util.Locale;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Derives the server's allowed filesystem root for the CVE-2025-53110 prefix-sibling oracle,
 * WITHOUT reading any out-of-root secret.
 *
 * <p>Two strategies, in priority order:
 * <ol>
 *   <li><b>Read-only discovery tool.</b> If the server exposes a {@code list_allowed_directories}
 *       -style tool, call it and parse the first absolute path out of its text. The live
 *       {@code @modelcontextprotocol/server-filesystem} build returns
 *       {@code "Allowed directories:\n/private/tmp/.../allow"}.</li>
 *   <li><b>Leaked root in a rejection error.</b> Probe the path argument with a clearly-outside
 *       absolute path; a bounded server denies with {@code "Access denied - path outside allowed
 *       directories: <probed> not in <root>"} and the root can be parsed from that error.</li>
 * </ol>
 *
 * <p>If neither yields a USABLE root the prefix-sibling tier is skipped entirely — no root means no
 * probe and therefore no finding and no false positive. A degenerate root (empty, a bare separator,
 * a Windows drive root with no segment) has no parent directory to escape from and yields no
 * sibling probe, so {@link #prefixSiblingPath} returns {@code null} and the tier safely skips.
 */
final class AllowedRootDeriver {

    private AllowedRootDeriver() {}

    private static final String SIBLING_MARKER = "_mcpscan_";
    private static final Pattern ABSOLUTE_PATH =
            Pattern.compile("(/[^\\s\"'`,;)]+|[A-Za-z]:\\\\[^\\s\"'`,;)]+)");
    // "...not in <root>" — the tail of server-filesystem's access-denied message names the root.
    private static final Pattern NOT_IN_ROOT =
            Pattern.compile("not in\\s+(/[^\\s\"'`,;)]+|[A-Za-z]:\\\\[^\\s\"'`,;)]+)");

    private static final List<String> ALLOWED_DIR_TOOL_NAMES = List.of(
            "list_allowed_directories",
            "list_allowed_dirs",
            "allowed_directories",
            "get_allowed_directories"
    );

    /**
     * A path that is provably outside any plausible sandbox AND shares no plausible root prefix,
     * used as BOTH the root-deriving probe (its rejection names the root) and the prefix-sibling
     * DENY-CONTROL (a bounded server must deny it). Never read; only its rejection message matters.
     */
    static final String DENY_CONTROL_PATH = "/mcpscan-nonexistent-" + SIBLING_MARKER + "root";

    /**
     * @param discoveryToolNames names of every discovered tool (to find a list-allowed-directories tool)
     * @param noArgToolCall       invokes a discovered tool by name with empty arguments
     * @param argumentProbe       sends a value through the path argument under test
     */
    static String derive(List<String> discoveryToolNames,
                         Function<String, HttpRequestResponse> noArgToolCall,
                         Function<String, HttpRequestResponse> argumentProbe) {
        String fromTool = deriveFromDiscoveryTool(discoveryToolNames, noArgToolCall);
        if (fromTool != null) {
            return fromTool;
        }
        return deriveFromRejection(argumentProbe);
    }

    private static String deriveFromDiscoveryTool(List<String> discoveryToolNames,
                                                  Function<String, HttpRequestResponse> noArgToolCall) {
        for (String toolName : discoveryToolNames) {
            if (!ALLOWED_DIR_TOOL_NAMES.contains(toolName.toLowerCase(Locale.ROOT))) {
                continue;
            }
            String root = firstAbsolutePath(joinedText(noArgToolCall.apply(toolName)));
            if (root != null) {
                return root;
            }
        }
        return null;
    }

    private static String deriveFromRejection(Function<String, HttpRequestResponse> argumentProbe) {
        HttpRequestResponse response = argumentProbe.apply(DENY_CONTROL_PATH);
        Matcher matcher = NOT_IN_ROOT.matcher(joinedText(response));
        return matcher.find() ? matcher.group(1) : null;
    }

    /**
     * The probe path for a NON-EXISTENT sibling that shares the root's string prefix:
     * {@code <root>_mcpscan_<marker>/<random>}. A naive {@code startsWith(root)} containment check
     * passes (the prefix matches) and the server then fails to open the missing file; a correctly
     * bounded server denies the path before touching the filesystem.
     *
     * @return the sibling probe path, or {@code null} for a degenerate root that has no segment to
     * share a prefix with (empty, blank, a bare {@code /} or {@code \}, or a bare drive root such
     * as {@code C:\}) — the caller skips the tier rather than emit a malformed probe.
     */
    static String prefixSiblingPath(String allowedRoot) {
        if (!hasShareablePrefixSegment(allowedRoot)) {
            return null;
        }
        String marker = Integer.toHexString(ThreadLocalRandom.current().nextInt());
        String random = Integer.toHexString(ThreadLocalRandom.current().nextInt());
        return stripTrailingSeparator(allowedRoot) + SIBLING_MARKER + marker + "/" + random;
    }

    /**
     * A root has a shareable prefix segment only if, after stripping any trailing separator, it
     * still has a non-empty final path segment whose name a sibling can extend. Bare roots
     * ({@code /}, {@code \}, {@code C:\}, {@code C:/}) and empty/blank roots have no such segment.
     */
    private static boolean hasShareablePrefixSegment(String root) {
        if (root == null || root.isBlank()) {
            return false;
        }
        String trimmed = stripTrailingSeparator(root);
        int lastSeparator = Math.max(trimmed.lastIndexOf('/'), trimmed.lastIndexOf('\\'));
        String lastSegment = trimmed.substring(lastSeparator + 1);
        // A Windows drive root (C:) left after stripping the trailing separator has no real
        // segment to extend — its only "segment" is the drive letter + colon.
        if (lastSegment.isEmpty() || lastSegment.endsWith(":")) {
            return false;
        }
        return true;
    }

    private static String firstAbsolutePath(String text) {
        Matcher matcher = ABSOLUTE_PATH.matcher(text);
        return matcher.find() ? matcher.group(1) : null;
    }

    private static String joinedText(HttpRequestResponse response) {
        if (response == null) {
            return "";
        }
        return String.join("\n", ToolCallTextExtractor.allTextFromResponse(response));
    }

    private static String stripTrailingSeparator(String value) {
        if (value.endsWith("/") || value.endsWith("\\")) {
            return value.substring(0, value.length() - 1);
        }
        return value;
    }
}
