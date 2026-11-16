package com.mcpscanner.access;

import com.mcpscanner.checks.api.AccessFinding;
import com.mcpscanner.checks.api.AccessOutcome;
import com.mcpscanner.checks.api.Principal;

import java.util.List;
import java.util.Optional;

public record AccessCell(ListingState listing, Optional<AccessOutcome> outcome, boolean anomaly,
                         List<AccessFinding> findings, Optional<Principal> sameCredentialsAs,
                         Optional<String> notComparedReason) {

    public AccessCell {
        findings = List.copyOf(findings);
    }

    public AccessCell(ListingState listing, Optional<AccessOutcome> outcome, boolean anomaly,
                      List<AccessFinding> findings, Optional<Principal> sameCredentialsAs) {
        this(listing, outcome, anomaly, findings, sameCredentialsAs, Optional.empty());
    }

    public static AccessCell of(ListingState listing, Optional<AccessOutcome> outcome, boolean anomaly) {
        return new AccessCell(listing, outcome, anomaly, List.of(), Optional.empty());
    }

    AccessCell withNotComparedReason(Optional<String> reason) {
        return new AccessCell(listing, outcome, anomaly, findings, sameCredentialsAs,
                reason.filter(why -> outcome.equals(Optional.of(AccessOutcome.NOT_RUN))));
    }

    public boolean checked() {
        return outcome.isPresent();
    }

    public boolean reported() {
        return findings.stream().anyMatch(AccessFinding::reported);
    }

    public boolean possible() {
        return findings.stream().anyMatch(finding -> !finding.reported());
    }

    public boolean reportedExpectationBreach() {
        return findings.stream().anyMatch(AccessFinding::breaksExpectation);
    }

    boolean differsFromOwner() {
        return outcome.filter(value -> value != AccessOutcome.SAME_RESULT).isPresent();
    }
}
