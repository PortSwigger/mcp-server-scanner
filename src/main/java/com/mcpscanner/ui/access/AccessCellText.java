package com.mcpscanner.ui.access;

import com.mcpscanner.access.AccessCell;
import com.mcpscanner.access.AccessItem;
import com.mcpscanner.access.AccessRow;
import com.mcpscanner.access.ListingState;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

final class AccessCellText {

    static final String ANOMALY = "⚠ ";
    private static final String SEPARATOR = " · ";

    private AccessCellText() {
    }

    static String item(AccessItem item) {
        return (item.key().kind() == AccessItemKey.Kind.TOOL ? "tool  " : "resource  ") + item.key().name();
    }

    static String expectation(AccessRow row) {
        return ExpectationText.label(row) + (row.inferred() ? " (inferred)" : "");
    }

    static String identity(AccessRow row, Principal principal) {
        AccessCell cell = row.cell(principal.id());
        return row.unconfirmedSameResult(principal) ? identity(cell, false, unconfirmedSameResult(row))
                : identity(cell, row.ownedBy(principal));
    }

    static String unconfirmedSameResult(AccessRow row) {
        return "? same result as " + row.owner().name() + " — allowed? Set Who should reach it";
    }

    static String identity(AccessCell cell, boolean owner) {
        return identity(cell, owner, outcomeOrPending(cell));
    }

    private static String identity(AccessCell cell, boolean owner, String outcome) {
        List<String> parts = new ArrayList<>();
        listing(cell.listing()).ifPresent(parts::add);
        if (owner) {
            parts.add("owner");
        } else if (cell.sameCredentialsAs().isPresent()) {
            parts.add("= same credentials as " + cell.sameCredentialsAs().get().name());
        } else {
            parts.add(outcome);
            findingMark(cell).ifPresent(parts::add);
        }
        return flagged(cell, String.join(SEPARATOR, parts));
    }

    static String anonymous(AccessCell cell) {
        return flagged(cell, outcomeOrPending(cell));
    }

    static String outcome(AccessOutcome outcome) {
        return switch (outcome) {
            case SAME_RESULT -> "✓ same result";
            case DIFFERENT_RESULT -> "✓ different result";
            case REFUSED -> "✗ refused";
            case SKIPPED_WRITE -> "— skipped (write)";
            case NOT_RUN -> "— not compared";
            case ERROR -> "! no answer";
        };
    }

    private static Optional<String> findingMark(AccessCell cell) {
        if (cell.reported()) {
            return Optional.of("⚑ issue");
        }
        return cell.possible() ? Optional.of("? possible leak") : Optional.empty();
    }

    private static String outcomeOrPending(AccessCell cell) {
        return cell.outcome().map(AccessCellText::outcome).orElse(AccessInfoNote.NOT_YET_CHECKED);
    }

    private static Optional<String> listing(ListingState listing) {
        return switch (listing) {
            case LISTED -> Optional.of("● listed");
            case HIDDEN -> Optional.of("○ hidden");
            case NOT_DISCOVERED -> Optional.of("? not discovered");
            case NO_LISTING -> Optional.empty();
        };
    }

    private static String flagged(AccessCell cell, String text) {
        return cell.anomaly() ? ANOMALY + text : text;
    }
}
