package com.mcpscanner.checks;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Hardens {@link AllowedRootDeriver#prefixSiblingPath} against pathological roots: a degenerate
 * root must SKIP (return {@code null}) rather than emit a malformed probe, and a usable root must
 * yield a well-formed prefix-sharing sibling with no path-injection.
 */
class AllowedRootDeriverTest {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            " ",          // blank
            "/",          // bare POSIX root
            "\\",         // bare Windows separator
            "C:\\",       // Windows drive root, trailing separator
            "C:/",        // Windows drive root, forward slash
            "C:",         // bare drive letter, no segment
            "///",        // multiple separators, no segment
    })
    void degenerateRootYieldsNoSiblingProbe(String root) {
        assertThat(AllowedRootDeriver.prefixSiblingPath(root)).isNull();
    }

    @Test
    void usableRootYieldsPrefixSharingSibling() {
        String sibling = AllowedRootDeriver.prefixSiblingPath("/srv/workspace");

        assertThat(sibling).startsWith("/srv/workspace_mcpscan_");
        // The sibling extends the root's last segment, so it shares the full root string prefix.
        assertThat(sibling).contains("/srv/workspace");
    }

    @Test
    void trailingSlashRootIsNormalisedBeforeBuildingTheSibling() {
        String sibling = AllowedRootDeriver.prefixSiblingPath("/srv/workspace/");

        // No double slash and no empty segment: the trailing separator is stripped first.
        assertThat(sibling).startsWith("/srv/workspace_mcpscan_");
        assertThat(sibling).doesNotContain("//");
    }

    @Test
    void windowsDriveRootedPathYieldsSibling() {
        String sibling = AllowedRootDeriver.prefixSiblingPath("C:\\workspace");

        assertThat(sibling).startsWith("C:\\workspace_mcpscan_");
    }

    @Test
    void multiByteAndPercentCharactersInRootAreCarriedVerbatimWithNoInjection() {
        // A root containing percent and multi-byte characters must not break the probe or inject
        // extra path separators — the marker is appended to the existing last segment as-is.
        String root = "/srv/wörk%2fspace";
        String sibling = AllowedRootDeriver.prefixSiblingPath(root);

        assertThat(sibling).startsWith(root + "_mcpscan_");
        // Exactly one separator beyond the root string (the marker, then one slash before random).
        assertThat(sibling.substring(root.length())).matches("_mcpscan_[0-9a-f]+/[0-9a-f]+");
    }
}
