package com.mcpscanner.access;

import com.mcpscanner.checks.api.AccessExpectation;
import com.mcpscanner.checks.api.AccessItemKey;
import com.mcpscanner.checks.api.CredentialCopies;
import com.mcpscanner.checks.api.Principal;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

final class AccessRowFactory {

    private final AccessExpectations expectations;
    private final AccessOutcomes outcomes;

    AccessRowFactory(AccessExpectations expectations, AccessOutcomes outcomes) {
        this.expectations = expectations;
        this.outcomes = outcomes;
    }

    AccessRow row(ListedItem listed, List<Principal> principals) {
        AccessItemKey key = listed.item().key();
        Optional<AccessExpectation> stored = expectations.stored(key);
        CredentialCopies copies = new CredentialCopies(listed.owner(), principals);
        AccessExpectation expectation = stored.orElseGet(() -> ExpectationInference.infer(listed, principals, copies));
        Map<String, AccessCell> cells = new LinkedHashMap<>();
        principals.forEach(principal -> cells.put(principal.id(),
                cell(listed, principal, expectation, copies.originalOf(principal))));
        return new AccessRow(listed.item(), listed.owner(), expectation, stored.isEmpty(), cells,
                anonymousCell(key, expectation));
    }

    private AccessCell cell(ListedItem listed, Principal principal, AccessExpectation expectation,
                            Optional<Principal> original) {
        AccessItemKey key = listed.item().key();
        if (original.isPresent()) {
            return new AccessCell(listed.listing(principal), Optional.empty(), false, List.of(), original);
        }
        var outcome = outcomes.outcome(key, principal.id());
        var findings = outcomes.findings(key, principal.id());
        boolean anomaly = AnomalyRule.identityBreaks(expectation, listed.owner(), principal, outcome, findings);
        return new AccessCell(listed.listing(principal), outcome, anomaly, findings, Optional.empty())
                .withNotComparedReason(outcomes.notCompared(key));
    }

    private AccessCell anonymousCell(AccessItemKey key, AccessExpectation expectation) {
        var outcome = outcomes.anonymous(key);
        return AccessCell.of(ListingState.NO_LISTING, outcome, AnomalyRule.anonymousBreaks(expectation, outcome))
                .withNotComparedReason(outcomes.notCompared(key));
    }
}
