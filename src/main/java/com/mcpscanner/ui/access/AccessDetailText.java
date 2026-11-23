package com.mcpscanner.ui.access;

import com.mcpscanner.access.AccessCell;
import com.mcpscanner.access.AccessRow;
import com.mcpscanner.access.ListingState;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.crossidentity.SyntheticLabel;

import java.util.ArrayList;
import java.util.List;

final class AccessDetailText {

    private static final String BULLET = "• ";

    private AccessDetailText() {
    }

    static String describe(AccessRow row, AccessColumn column) {
        if (column instanceof AccessColumn.Identity identity) {
            return identity(row, identity.principal());
        }
        return column instanceof AccessColumn.Synthetic synthetic ? synthetic(row, synthetic) : item(row);
    }

    private static String item(AccessRow row) {
        List<String> lines = new ArrayList<>();
        lines.add(name(row) + " — owned by " + PrincipalLabels.described(row.owner()));
        lines.add(BULLET + expectation(row) + " Change it in the last column.");
        lines.add(BULLET + summary(row));
        if (row.item().writes()) {
            lines.add(BULLET + "Write tools (destructive or unannotated) are only replayed after you confirm, as in Scan.");
        }
        return String.join("\n", lines);
    }

    private static String identity(AccessRow row, Principal principal) {
        AccessCell cell = row.cell(principal.id());
        List<String> lines = new ArrayList<>();
        lines.add(name(row) + " — " + PrincipalLabels.described(principal));
        lines.add(BULLET + listing(row, cell, principal));
        if (row.ownedBy(principal)) {
            lines.add(BULLET + principal.name() + " owns this item: its own call is the baseline every other "
                    + "identity is compared with.");
        } else if (cell.sameCredentialsAs().isPresent()) {
            lines.add(BULLET + "Same credentials as " + cell.sameCredentialsAs().get().name() + " — not compared. Give "
                    + principal.name() + " another account's credentials on the Users tab to compare it.");
        } else {
            lines.add(BULLET + identityOutcome(row, cell, principal));
            if (row.unconfirmedSameResult(principal)) {
                lines.add(BULLET + unconfirmedSameResult(row, principal));
            }
            lines.add(BULLET + expectation(row) + verdict(cell));
            AccessFindingText.lines(row, cell).forEach(line -> lines.add(BULLET + line));
        }
        return String.join("\n", lines);
    }

    private static String synthetic(AccessRow row, AccessColumn.Synthetic column) {
        AccessCell cell = row.synthetic(column.principalId());
        String outcome = cell.outcome().map(value -> syntheticOutcome(row, cell, value, column.withThe()))
                .orElse("Not called yet. Check access also replays this " + method(row) + " "
                        + lowered(column.withThe()) + ".");
        List<String> lines = new ArrayList<>();
        lines.add(name(row) + " — " + column.described());
        if (cell.listing() != ListingState.NO_LISTING) {
            lines.add(BULLET + listing(row, cell, column.title()));
        }
        lines.add(BULLET + outcome);
        lines.add(BULLET + expectation(row) + verdict(cell));
        return String.join("\n", lines);
    }

    private static String listing(AccessRow row, AccessCell cell, Principal principal) {
        return listing(row, cell, principal.name());
    }

    private static String listing(AccessRow row, AccessCell cell, String lister) {
        String list = row.item().key().kind() == AccessItemKey.Kind.TOOL ? "tools/list" : "resources/list";
        return switch (cell.listing()) {
            case LISTED -> "Listed in " + lister + "'s own " + list + ".";
            case HIDDEN -> "Not in " + lister + "'s own " + list + ".";
            case NOT_DISCOVERED, NO_LISTING -> lister + "'s own " + list + " has not been discovered.";
        };
    }

    private static String identityOutcome(AccessRow row, AccessCell cell, Principal principal) {
        String owner = row.owner().name();
        return cell.outcome().map(outcome -> switch (outcome) {
            case SAME_RESULT -> "Calling it as " + principal.name() + " returned the same result as " + owner + ".";
            case DIFFERENT_RESULT -> "Calling it as " + principal.name() + " succeeded with a different result from "
                    + owner + "'s.";
            case REFUSED -> "Calling it as " + principal.name() + " was refused.";
            case SKIPPED_WRITE -> "Not replayed: it is a write tool and replaying it was not confirmed.";
            case NOT_RUN -> notCompared(cell, "Not compared");
            case ERROR -> "The replay as " + principal.name() + " got no answer.";
        }).orElse("Not called yet. Check access replays this " + method(row) + " as " + principal.name()
                + " and compares it with " + owner + ".");
    }

    private static String syntheticOutcome(AccessRow row, AccessCell cell, AccessOutcome outcome, String withThe) {
        return switch (outcome) {
            case SAME_RESULT -> withThe + " the call returned the same result as " + row.owner().name()
                    + ". Scan this item with the unauthenticated request execution check to report it.";
            case DIFFERENT_RESULT -> withThe + " the call succeeded with a different result.";
            case REFUSED -> withThe + " the call was refused, so this is not an unauthenticated-access issue.";
            case SKIPPED_WRITE -> "Not compared " + lowered(withThe) + ".";
            case NOT_RUN -> notCompared(cell, "Not compared " + lowered(withThe));
            case ERROR -> "The call " + lowered(withThe) + " got no answer.";
        };
    }

    private static String lowered(String phrase) {
        return Character.toLowerCase(phrase.charAt(0)) + phrase.substring(1);
    }

    private static String unconfirmedSameResult(AccessRow row, Principal principal) {
        return "Same result as " + row.owner().name() + " — allowed? " + principal.name() + " is lower privilege "
                + "and the expectation is only inferred. If " + principal.name() + " should not reach it, set Who "
                + "should reach it (double-click this cell).";
    }

    private static String notCompared(AccessCell cell, String lead) {
        return lead + cell.notComparedReason().map(reason -> ": " + reason).orElse("") + ".";
    }

    private static String expectation(AccessRow row) {
        return "Expected: “" + ExpectationText.label(row) + "”"
                + (row.inferred() ? " (inferred from which identities list it)." : " (set by you).");
    }

    private static String verdict(AccessCell cell) {
        if (!cell.checked()) {
            return "";
        }
        if (cell.reportedExpectationBreach()) {
            return " → Breaks the expectation: the check reported an issue in Burp's site map.";
        }
        return cell.anomaly() ? " → Breaks the expectation." : " → Consistent with the expectation.";
    }

    private static String summary(AccessRow row) {
        if (!row.checked()) {
            return "Not called yet. Check access replays this " + method(row) + " as each compared user, "
                    + SyntheticLabel.ALWAYS_COMPARED + ", and compares the results with " + row.owner().name() + "'s.";
        }
        long anomalies = row.anomalies();
        String breaches = anomalies == 0 ? "No identity reaches it against the expectation."
                : anomalies + (anomalies == 1 ? " cell breaks" : " cells break") + " the expectation.";
        return breaches + AccessFindingText.counts(row);
    }

    private static String method(AccessRow row) {
        return row.item().key().kind() == AccessItemKey.Kind.TOOL ? "tools/call" : "resources/read";
    }

    private static String name(AccessRow row) {
        return row.item().key().name();
    }
}
