package com.mcpscanner.ui.access;

import com.mcpscanner.access.AccessRow;
import com.mcpscanner.checks.api.AccessExpectation;

final class ExpectationText {

    static final String NEUTRAL_OWNER = "the owner";

    private ExpectationText() {
    }

    static String label(AccessRow row) {
        return label(row.expectation(), row.owner().name());
    }

    static String label(AccessExpectation expectation, String owner) {
        return owner.isBlank() ? sentenceCase(phrase(expectation, NEUTRAL_OWNER)) : phrase(expectation, owner);
    }

    static String tooltip(AccessExpectation expectation, String owner) {
        String name = owner.isBlank() ? NEUTRAL_OWNER : owner;
        return switch (expectation) {
            case SHARED_BY_DESIGN -> "Nobody is flagged, and results are not compared between users "
                    + "(e.g. a public catalogue).";
            case ANY_SIGNED_IN -> "Anyone may call it; a user is flagged only if they get " + name
                    + "'s data back (e.g. get_my_profile).";
            case NOT_LOWER -> "Lower-privilege users are flagged for any successful call.";
            case HIGHER_ONLY -> "Lower-privilege and same-level users are flagged for any successful call.";
            case OWNER_ONLY -> "Every user other than " + name + " is flagged for any successful call, even with "
                    + "their own data (e.g. delete_user, run_sql).";
        };
    }

    private static String phrase(AccessExpectation expectation, String owner) {
        return switch (expectation) {
            case SHARED_BY_DESIGN -> "Anyone — same result for everyone";
            case ANY_SIGNED_IN -> "Anyone — but only their own data";
            case NOT_LOWER -> owner + "'s level or above";
            case HIGHER_ONLY -> "Only users above " + owner + "'s level";
            case OWNER_ONLY -> "Only " + owner;
        };
    }

    private static String sentenceCase(String text) {
        return Character.toUpperCase(text.charAt(0)) + text.substring(1);
    }
}
