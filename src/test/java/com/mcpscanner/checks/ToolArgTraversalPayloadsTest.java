package com.mcpscanner.checks;

import com.mcpscanner.checks.ToolArgTraversalPayloads.ToolArgPayload;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

class ToolArgTraversalPayloadsTest {

    private static final String SINGLE_ENCODED_PASSWD =
            "..%2f".repeat(TraversalEscapes.DEEP_LEVELS) + "etc%2fpasswd";
    private static final String DOUBLE_ENCODED_PASSWD =
            "..%252f".repeat(TraversalEscapes.DEEP_LEVELS) + "etc%2fpasswd";

    @Test
    void exposesSingleEncodedSlashPasswdPayload() {
        // Regression lock: a single-encoded %2f traversal variant must remain in the list. Pinned to
        // the canonical deep prefix (excess ../ clamps at the filesystem root), not a shallow ../x3.
        assertThat(allPayloadValues()).contains(SINGLE_ENCODED_PASSWD);
    }

    @Test
    void includesDoubleEncodedTraversalPayload() {
        // WAFs and path-normalisers commonly strip a single round of percent-decoding, so a
        // `%25` (encoded `%`) doubles up the `%2f` to land as a literal `..%2f...` after one
        // decode pass — which then gets resolved by the server's filesystem layer.
        assertThat(allPayloadValues()).contains(DOUBLE_ENCODED_PASSWD);
    }

    @Test
    void doubleEncodedPayloadExpectsPasswdSignature() {
        ToolArgPayload doubleEncoded = ToolArgTraversalPayloads.all().stream()
                .filter(p -> DOUBLE_ENCODED_PASSWD.equals(p.value()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("double-encoded payload missing"));

        assertThat(doubleEncoded.expectedSignatures()).containsExactly(FileSignature.PASSWD);
    }

    @Test
    void plainTraversalPayloadsUseTheDeepAndShallowLiteralPrefixes() {
        // Parity with ResourceTraversalPayloads: the tool-arg family emits the SAME small principled
        // {deep, shallow} literal set — the deep prefix reaches a normalise-then-check handler, the
        // shallow companion reaches a raw-prefilter handler that would reject the deep prefix.
        String deepPrefix = "../".repeat(TraversalEscapes.DEEP_LEVELS);
        String shallowPrefix = "../".repeat(TraversalEscapes.SHALLOW_LEVELS);
        List<ToolArgPayload> plain = ToolArgTraversalPayloads.all().stream()
                .filter(payload -> payload.tier() == PathTraversalTier.TRAVERSAL)
                .toList();

        assertThat(plain)
                .isNotEmpty()
                .allSatisfy(payload -> assertThat(payload.value()).startsWith("../"));
        assertThat(plain).anySatisfy(payload -> assertThat(payload.value()).startsWith(deepPrefix));
        assertThat(plain).anySatisfy(payload -> assertThat(payload.value()).startsWith(shallowPrefix));
    }

    @Test
    void everyPayloadIsClassifiedIntoExactlyOneTier() {
        assertThat(ToolArgTraversalPayloads.all())
                .allSatisfy(payload -> assertThat(payload.tier()).isNotNull());
    }

    @Test
    void traversalTierPayloadsAllContainADotDotEscape() {
        assertThat(ToolArgTraversalPayloads.all())
                .filteredOn(payload -> payload.tier() == PathTraversalTier.TRAVERSAL)
                .isNotEmpty()
                .allSatisfy(payload ->
                        assertThat(PathTraversalTierInvariant.hasDotDotEscape(payload.value()))
                                .as("traversal payload %s must contain a dot-dot escape", payload.value())
                                .isTrue());
    }

    @Test
    void absoluteTierPayloadsContainNoDotDotEscape() {
        assertThat(ToolArgTraversalPayloads.all())
                .filteredOn(payload -> payload.tier() == PathTraversalTier.ABSOLUTE)
                .isNotEmpty()
                .allSatisfy(payload ->
                        assertThat(PathTraversalTierInvariant.hasDotDotEscape(payload.value()))
                                .as("absolute payload %s must not contain a dot-dot escape", payload.value())
                                .isFalse());
    }

    @Test
    void absoluteTierHoldsRootedPathsAndFileUris() {
        assertThat(absoluteTierValues())
                .contains("/etc/passwd", "C:\\Windows\\win.ini", "file:///etc/passwd");
    }

    @Test
    void encodingBypassTwinsShareDifferentialKeyWithTheirPlainTraversal() {
        // The classifier promotes a group to ENCODING_BYPASS only when a plain ../ twin was
        // delivered-and-rejected; for that pairing to work every encoded twin MUST share its
        // plain traversals' differentialKey. Each differential group carries the {deep, shallow}
        // plain TRAVERSAL anchors plus >= 1 ENCODING_BYPASS twin, all under the one key.
        Map<String, List<ToolArgPayload>> byKey = ToolArgTraversalPayloads.all().stream()
                .filter(p -> p.tier() == PathTraversalTier.TRAVERSAL
                        || p.tier() == PathTraversalTier.ENCODING_BYPASS)
                .collect(Collectors.groupingBy(ToolArgPayload::differentialKey));

        assertThat(byKey).isNotEmpty();
        assertThat(byKey.values()).allSatisfy(group -> {
            assertThat(group).filteredOn(p -> p.tier() == PathTraversalTier.TRAVERSAL)
                    .as("each differential group carries the deep + shallow plain traversal anchors")
                    .hasSize(2);
            assertThat(group).filteredOn(p -> p.tier() == PathTraversalTier.ENCODING_BYPASS)
                    .as("each differential group pairs the plain anchors with encoded twins")
                    .isNotEmpty();
        });
    }

    @Test
    void absolutePayloadsDoNotShareDifferentialKeysWithTraversalGroups() {
        // ABSOLUTE payloads must key independently so they never fold into a traversal differential
        // group (which would let an absolute hit masquerade as a TRAVERSAL/ENCODING_BYPASS).
        List<String> traversalKeys = ToolArgTraversalPayloads.all().stream()
                .filter(p -> p.tier() == PathTraversalTier.TRAVERSAL
                        || p.tier() == PathTraversalTier.ENCODING_BYPASS)
                .map(ToolArgPayload::differentialKey)
                .toList();

        assertThat(ToolArgTraversalPayloads.all())
                .filteredOn(p -> p.tier() == PathTraversalTier.ABSOLUTE)
                .allSatisfy(p -> assertThat(traversalKeys).doesNotContain(p.differentialKey()));
    }

    private static List<String> allPayloadValues() {
        return ToolArgTraversalPayloads.all().stream()
                .map(ToolArgPayload::value)
                .toList();
    }

    private static List<String> absoluteTierValues() {
        return ToolArgTraversalPayloads.all().stream()
                .filter(payload -> payload.tier() == PathTraversalTier.ABSOLUTE)
                .map(ToolArgPayload::value)
                .toList();
    }
}
