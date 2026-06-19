package com.mcpscanner.checks;

import java.util.regex.Pattern;

/**
 * Shared tier-contract regexes so the resource and tool-argument payload suites assert the same
 * invariants: a TRAVERSAL value must contain a dot-dot escape, an ENCODING_BYPASS value must
 * contain an <em>encoded</em> dot-dot/segment escape, and an ABSOLUTE value must contain neither.
 * ENCODED_ESCAPE deliberately does not match a bare {@code %2f}/{@code %5c} (an absolute URI such
 * as {@code file:///etc%2Fpasswd} percent-encodes its slashes without escaping any directory), so
 * the "ABSOLUTE contains neither escape" half of the contract is genuinely testable.
 */
final class PathTraversalTierInvariant {

    private PathTraversalTierInvariant() {}

    static final Pattern DOT_DOT_ESCAPE = Pattern.compile(
            "\\.\\.[/\\\\]"          // ../  or ..\
                    + "|\\.\\.%2f"   // ..%2f
                    + "|\\.\\.%5c"   // ..%5c
                    + "|\\.\\.%252f" // ..%252f (double-encoded)
                    + "|%2e%2e"      // %2e%2e
                    + "|%c0%ae"      // overlong UTF-8 dot
                    + "|\\.\\.\\.\\.//", // ....//
            Pattern.CASE_INSENSITIVE);

    static final Pattern ENCODED_ESCAPE = Pattern.compile(
            "%2e%2e"                 // encoded dot-dot
                    + "|%252e"       // double-encoded dot
                    + "|\\.\\.%2f"   // ..%2f
                    + "|\\.\\.%5c"   // ..%5c
                    + "|\\.\\.%252f" // ..%252f (double-encoded)
                    + "|%c0%ae"      // overlong UTF-8 dot
                    + "|%c0%af"      // overlong UTF-8 slash
                    + "|%00"         // null-byte truncation bypass
                    + "|\\.\\.\\.\\.//", // dot-doubling normalises to ../
            Pattern.CASE_INSENSITIVE);

    static boolean hasDotDotEscape(String value) {
        return DOT_DOT_ESCAPE.matcher(value).find();
    }

    static boolean hasEncodedEscape(String value) {
        return ENCODED_ESCAPE.matcher(value).find();
    }
}
