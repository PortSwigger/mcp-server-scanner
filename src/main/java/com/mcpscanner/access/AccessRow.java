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
import java.util.stream.Stream;

public record AccessRow(AccessItem item, Principal owner, AccessExpectation expectation, boolean inferred,
                        Map<String, AccessCell> cells, Map<String, AccessCell> synthetic) {

    private static final AccessCell UNLISTED = AccessCell.of(ListingState.NO_LISTING, Optional.empty(), false);

    public AccessRow {
        cells = Collections.unmodifiableMap(new LinkedHashMap<>(cells));
        synthetic = Collections.unmodifiableMap(new LinkedHashMap<>(synthetic));
    }

    public AccessRow(AccessItem item, Principal owner, AccessExpectation expectation, boolean inferred,
                     Map<String, AccessCell> cells, AccessCell anonymous) {
        this(item, owner, expectation, inferred, cells, Map.of(Principal.ANONYMOUS_ID, anonymous));
    }

    public AccessCell anonymous() {
        return synthetic(Principal.ANONYMOUS_ID);
    }

    public AccessCell synthetic(String principalId) {
        return synthetic.getOrDefault(principalId, UNLISTED);
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
        return allCells().filter(AccessCell::anomaly).count();
    }

    public long issues() {
        return cells.values().stream().filter(AccessCell::reported).count();
    }

    public long possibleFindings() {
        return cells.values().stream().filter(AccessCell::possible).count();
    }

    public boolean checked() {
        return allCells().anyMatch(AccessCell::checked);
    }

    boolean differs() {
        return anomalies() > 0 || listingsDiffer() || cells.values().stream().anyMatch(AccessCell::differsFromOwner);
    }

    private boolean listingsDiffer() {
        return allCells().map(AccessCell::listing)
                .filter(listing -> listing != ListingState.NOT_DISCOVERED && listing != ListingState.NO_LISTING)
                .distinct().count() > 1;
    }

    private Stream<AccessCell> allCells() {
        return Stream.concat(cells.values().stream(), synthetic.values().stream());
    }
}
