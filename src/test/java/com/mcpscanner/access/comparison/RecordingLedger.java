package com.mcpscanner.access.comparison;

import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessFinding;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.AccessLedger;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.PrincipalListings;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

final class RecordingLedger implements AccessLedger, PrincipalListings {

    static final String ANONYMOUS = "(anonymous)";

    private AccessExpectation expectation = AccessExpectation.ANY_SIGNED_IN;
    private boolean replayPermitted = true;
    private boolean replaysWrites = true;
    private final Map<String, Boolean> listings = new HashMap<>();
    private final Map<String, AccessOutcome> outcomes = new LinkedHashMap<>();
    private final Map<String, List<AccessFinding>> findings = new LinkedHashMap<>();
    private Optional<String> notCompared = Optional.empty();

    RecordingLedger expecting(AccessExpectation value) {
        expectation = value;
        return this;
    }

    RecordingLedger replayingReads() {
        replaysWrites = false;
        return this;
    }

    RecordingLedger denyingReplay() {
        replayPermitted = false;
        return this;
    }

    RecordingLedger listing(String principalId, boolean listed) {
        listings.put(principalId, listed);
        return this;
    }

    Map<String, AccessOutcome> outcomes() {
        return Map.copyOf(outcomes);
    }

    Set<String> findings() {
        return Set.copyOf(findings.keySet());
    }

    List<AccessFinding> findingsOf(String principalId) {
        return List.copyOf(findings.getOrDefault(principalId, List.of()));
    }

    Optional<String> notCompared() {
        return notCompared;
    }

    @Override
    public void recordNotCompared(AccessItemKey item, String reason) {
        notCompared = Optional.of(reason);
    }

    @Override
    public void recordFinding(AccessItemKey item, String principalId, AccessFinding finding) {
        findings.computeIfAbsent(principalId, id -> new ArrayList<>()).add(finding);
    }

    @Override
    public AccessExpectation expectationFor(AccessItemKey item) {
        return expectation;
    }

    @Override
    public void record(AccessItemKey item, String principalId, AccessOutcome outcome) {
        outcomes.put(principalId, outcome);
    }

    @Override
    public void recordAnonymous(AccessItemKey item, AccessOutcome outcome) {
        outcomes.put(ANONYMOUS, outcome);
    }

    @Override
    public Optional<Boolean> lists(String principalId, AccessItemKey item) {
        return Optional.ofNullable(listings.get(principalId));
    }

    @Override
    public boolean permitsReplay(AccessItemKey item) {
        return replayPermitted;
    }

    @Override
    public boolean replaysWrite(AccessItemKey item) {
        return replaysWrites;
    }
}
