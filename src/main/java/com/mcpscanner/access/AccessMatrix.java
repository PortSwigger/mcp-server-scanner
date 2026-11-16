package com.mcpscanner.access;

import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessFinding;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;
import com.mcpscanner.checks.api.PrincipalRoster;
import com.mcpscanner.identity.discovery.DiscoveryOutcome;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

public final class AccessMatrix {

    private final Supplier<PrincipalRoster> roster;
    private final Supplier<Map<String, DiscoveryOutcome>> listings;
    private final AccessExpectations expectations;
    private final AccessOutcomes outcomes = new AccessOutcomes();
    private final AccessRowFactory rows;
    private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

    public AccessMatrix(Supplier<PrincipalRoster> roster, Supplier<Map<String, DiscoveryOutcome>> listings,
                        AccessExpectations expectations) {
        this.roster = roster;
        this.listings = listings;
        this.expectations = expectations;
        this.rows = new AccessRowFactory(expectations, outcomes);
    }

    public AccessSnapshot snapshot() {
        List<Principal> principals = principals();
        Map<String, DiscoveryOutcome> discovered = listings.get();
        List<AccessRow> built = new CatalogUnion(principals, discovered).items().stream()
                .map(item -> rows.row(item, principals))
                .toList();
        return new AccessSnapshot(discovered.get(Principal.PRIMARY_ID) instanceof DiscoveryOutcome.Listed,
                principals, built);
    }

    public Optional<AccessRow> row(AccessItemKey item) {
        List<Principal> principals = principals();
        return new CatalogUnion(principals, listings.get()).find(item).map(listed -> rows.row(listed, principals));
    }

    public AccessExpectation expectationFor(AccessItemKey item) {
        return row(item).map(AccessRow::expectation)
                .or(() -> expectations.stored(item))
                .orElse(AccessExpectation.ANY_SIGNED_IN);
    }

    public void setExpectation(AccessItemKey item, AccessExpectation expectation) {
        expectations.store(item, expectation);
        changed();
    }

    public void record(AccessItemKey item, String principalId, AccessOutcome outcome) {
        outcomes.record(item, principalId, outcome);
        changed();
    }

    public void recordAnonymous(AccessItemKey item, AccessOutcome outcome) {
        outcomes.recordAnonymous(item, outcome);
        changed();
    }

    public void recordFinding(AccessItemKey item, String principalId, AccessFinding finding) {
        outcomes.recordFinding(item, principalId, finding);
        changed();
    }

    public void recordNotCompared(AccessItemKey item, String reason) {
        outcomes.recordNotCompared(item, reason);
        changed();
    }

    public void clearOutcomes() {
        outcomes.clear();
        changed();
    }

    public void addListener(Runnable listener) {
        listeners.add(listener);
    }

    public void removeListener(Runnable listener) {
        listeners.remove(listener);
    }

    public void changed() {
        listeners.forEach(Runnable::run);
    }

    private List<Principal> principals() {
        PrincipalRoster current = roster.get();
        return current.all();
    }
}
