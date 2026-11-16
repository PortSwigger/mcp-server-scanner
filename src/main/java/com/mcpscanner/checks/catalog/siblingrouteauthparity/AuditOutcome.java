package com.mcpscanner.checks.catalog.siblingrouteauthparity;

import com.mcpscanner.checks.api.HostSettlement;

import java.util.Optional;

record AuditOutcome(Optional<Finding> finding, HostSettlement settlement) {

    static AuditOutcome found(Finding finding) {
        return new AuditOutcome(Optional.of(finding), HostSettlement.SETTLED);
    }

    static AuditOutcome settledWithoutFinding() {
        return new AuditOutcome(Optional.empty(), HostSettlement.SETTLED);
    }

    static AuditOutcome unsuitableSeed() {
        return new AuditOutcome(Optional.empty(), HostSettlement.UNSUITABLE_SEED);
    }

    static AuditOutcome of(Optional<Finding> finding) {
        return finding.map(AuditOutcome::found).orElseGet(AuditOutcome::settledWithoutFinding);
    }
}
