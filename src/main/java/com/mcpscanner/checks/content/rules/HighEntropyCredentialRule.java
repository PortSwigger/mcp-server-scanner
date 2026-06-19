package com.mcpscanner.checks.content.rules;

import com.mcpscanner.checks.content.ContentSuppression;

import java.util.regex.Pattern;

/**
 * Regex credential rule that additionally requires the matched token to carry real randomness.
 * Shaped-but-low-entropy placeholders (repeated/sequential filler such as {@code AIzaAAA...} or
 * {@code "A".repeat(24)}) satisfy the shape regex but are documentation, not live secrets.
 */
abstract class HighEntropyCredentialRule extends RegexContentRule {

    // Random base32/base62 secrets of >=16 chars score ~3.7-5.4 bits/char; shaped placeholders
    // (repeated or sequential filler) score under ~2.0. 3.0 sits in the empty gap between them.
    private static final double DEFAULT_MIN_ENTROPY_BITS_PER_CHAR = 3.0;

    HighEntropyCredentialRule(Pattern... patterns) {
        super(patterns);
    }

    @Override
    protected final boolean isSuppressedMatch(String match) {
        return isKnownPlaceholder(match) || belowEntropyFloor(match);
    }

    protected boolean isKnownPlaceholder(String match) {
        return false;
    }

    // Rules whose secret body uses a short, small-alphabet encoding (e.g. AWS's 16-char base32
    // body) sit closer to the placeholder gap and override this with a lower floor so genuine
    // keys in the lower tail of their distribution are not silently dropped.
    protected double minEntropyBitsPerChar() {
        return DEFAULT_MIN_ENTROPY_BITS_PER_CHAR;
    }

    private boolean belowEntropyFloor(String match) {
        return ContentSuppression.shannonEntropy(match) < minEntropyBitsPerChar();
    }
}
