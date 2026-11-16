package com.mcpscanner.ui.access;

import com.mcpscanner.access.AccessCell;
import com.mcpscanner.access.AccessRow;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;

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
        return column instanceof AccessColumn.Anonymous ? anonymous(row) : item(row);
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

    private static String anonymous(AccessRow row) {
        AccessCell cell = row.anonymous();
        String outcome = cell.outcome().map(value -> anonymousOutcome(row, cell, value))
                .orElse("Not called yet. Check access also replays this " + method(row) + " with no credentials.");
        return String.join("\n", name(row) + " — Anonymous (no credentials)", BULLET + outcome,
                BULLET + expectation(row) + verdict(cell));
    }

    private static String listing(AccessRow row, AccessCell cell, Principal principal) {
        String list = row.item().key().kind() == AccessItemKey.Kind.TOOL ? "tools/list" : "resources/list";
        return switch (cell.listing()) {
            case LISTED -> "Listed in " + principal.name() + "'s own " + list + ".";
            case HIDDEN -> "Not in " + principal.name() + "'s own " + list + ".";
            case NOT_DISCOVERED, NO_LISTING -> principal.name() + "'s own " + list + " has not been discovered.";
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

    private static String anonymousOutcome(AccessRow row, AccessCell cell, AccessOutcome outcome) {
        return switch (outcome) {
            case SAME_RESULT -> "Without credentials the call returned the same result as " + row.owner().name()
                    + ". Scan this item with the unauthenticated request execution check to report it.";
            case DIFFERENT_RESULT -> "Without credentials the call succeeded with a different result.";
            case REFUSED -> "Without credentials the call was refused, so this is not an unauthenticated-access issue.";
            case SKIPPED_WRITE -> "Not compared without credentials.";
            case NOT_RUN -> notCompared(cell, "Not compared without credentials");
            case ERROR -> "The anonymous replay got no answer.";
        };
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
            return "Not called yet. Check access replays this " + method(row) + " as each identity and Anonymous "
                    + "and compares the results with " + row.owner().name() + "'s.";
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
