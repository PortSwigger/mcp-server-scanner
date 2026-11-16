package com.mcpscanner.access;

import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRole;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public record AccessRow(AccessItem item, Principal owner, AccessExpectation expectation, boolean inferred,
                        Map<String, AccessCell> cells, AccessCell anonymous) {

    public AccessRow {
        cells = Collections.unmodifiableMap(new LinkedHashMap<>(cells));
    }

    public AccessCell cell(String principalId) {
        return cells.get(principalId);
    }

    public boolean ownedBy(Principal principal) {
        return owner.id().equals(principal.id());
    }

    public boolean unconfirmedSameResult(Principal principal) {
        AccessCell cell = cells.get(principal.id());
        return inferred && cell != null && !ownedBy(principal) && principal.role() == PrincipalRole.LOWER
                && !cell.anomaly() && cell.outcome().equals(Optional.of(AccessOutcome.SAME_RESULT));
    }

    public boolean unconfirmedSameResult(List<Principal> principals) {
        return principals.stream().anyMatch(this::unconfirmedSameResult);
    }

    public long anomalies() {
        return cells.values().stream().filter(AccessCell::anomaly).count() + (anonymous.anomaly() ? 1 : 0);
    }

    public long issues() {
        return cells.values().stream().filter(AccessCell::reported).count();
    }

    public long possibleFindings() {
        return cells.values().stream().filter(AccessCell::possible).count();
    }

    public boolean checked() {
        return anonymous.checked() || cells.values().stream().anyMatch(AccessCell::checked);
    }

    boolean differs() {
        return anomalies() > 0 || listingsDiffer() || cells.values().stream().anyMatch(AccessCell::differsFromOwner);
    }

    private boolean listingsDiffer() {
        return cells.values().stream().map(AccessCell::listing)
                .filter(listing -> listing != ListingState.NOT_DISCOVERED)
                .distinct().count() > 1;
    }
}
