package com.mcpscanner.checks;

import java.util.Collection;

/**
 * Resolves the reportable {@link PathTraversalTier} for one differential group (all the payloads
 * that share a {@code differentialKey}) from the tiers that actually disclosed an out-of-root file
 * plus whether the plain {@code ../} twin was delivered to the handler and rejected there.
 *
 * <p>Shared by the resource ({@code ResourcesReadProbeRunner}) and tool-argument
 * ({@code ToolsCallTraversalProbeRunner}) classifiers: the two runners differ in injection surface
 * (URI vs argument) and success-oracle shape ({@code result.contents} vs {@code result.content}),
 * but the tier-precedence decision over a differential group is identical, so it lives here once.
 *
 * <p>The honesty rule: {@code ENCODING_BYPASS} is only claimed with POSITIVE evidence the literal
 * {@code ../} reached the handler and was rejected (decode-after-check). An encoded-only hit with
 * no observed plain rejection is an ordinary {@code TRAVERSAL}, never an over-claimed broken
 * sanitizer.
 */
final class TraversalTierClassifier {

    private TraversalTierClassifier() {}

    static PathTraversalTier resolve(Collection<PathTraversalTier> hitTiers,
                                     boolean plainDeliveredAndRejected) {
        boolean plainTraversalHit = false;
        boolean encodedHit = false;
        boolean prefixSiblingHit = false;
        for (PathTraversalTier tier : hitTiers) {
            switch (tier) {
                case TRAVERSAL -> plainTraversalHit = true;
                case ENCODING_BYPASS -> encodedHit = true;
                case PREFIX_SIBLING -> prefixSiblingHit = true;
                case ABSOLUTE -> { /* folds into the encoded/plain decision below */ }
            }
        }
        if (prefixSiblingHit) {
            return PathTraversalTier.PREFIX_SIBLING;
        }
        if (plainTraversalHit) {
            return PathTraversalTier.TRAVERSAL;
        }
        if (encodedHit && plainDeliveredAndRejected) {
            return PathTraversalTier.ENCODING_BYPASS;
        }
        if (encodedHit) {
            return PathTraversalTier.TRAVERSAL;
        }
        return PathTraversalTier.ABSOLUTE;
    }
}
