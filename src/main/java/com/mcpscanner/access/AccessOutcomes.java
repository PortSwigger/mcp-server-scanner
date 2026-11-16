package com.mcpscanner.access;

import com.mcpscanner.checks.api.AccessFinding;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.AccessOutcome;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

final class AccessOutcomes {

    private final Map<CellKey, AccessOutcome> identities = new HashMap<>();
    private final Map<AccessItemKey, AccessOutcome> anonymous = new HashMap<>();
    private final Map<CellKey, List<AccessFinding>> findings = new HashMap<>();
    private final Map<AccessItemKey, String> notCompared = new HashMap<>();

    synchronized void record(AccessItemKey item, String principalId, AccessOutcome outcome) {
        CellKey cell = new CellKey(item, principalId);
        identities.put(cell, outcome);
        findings.remove(cell);
    }

    synchronized void recordAnonymous(AccessItemKey item, AccessOutcome outcome) {
        anonymous.put(item, outcome);
        notCompared.remove(item);
    }

    synchronized void recordNotCompared(AccessItemKey item, String reason) {
        notCompared.put(item, reason);
    }

    synchronized Optional<String> notCompared(AccessItemKey item) {
        return Optional.ofNullable(notCompared.get(item));
    }

    synchronized void recordFinding(AccessItemKey item, String principalId, AccessFinding finding) {
        findings.computeIfAbsent(new CellKey(item, principalId), cell -> new ArrayList<>()).add(finding);
    }

    synchronized Optional<AccessOutcome> outcome(AccessItemKey item, String principalId) {
        return Optional.ofNullable(identities.get(new CellKey(item, principalId)));
    }

    synchronized Optional<AccessOutcome> anonymous(AccessItemKey item) {
        return Optional.ofNullable(anonymous.get(item));
    }

    synchronized List<AccessFinding> findings(AccessItemKey item, String principalId) {
        return List.copyOf(findings.getOrDefault(new CellKey(item, principalId), List.of()));
    }

    synchronized void clear() {
        identities.clear();
        anonymous.clear();
        findings.clear();
        notCompared.clear();
    }

    private record CellKey(AccessItemKey item, String principalId) {
    }
}
