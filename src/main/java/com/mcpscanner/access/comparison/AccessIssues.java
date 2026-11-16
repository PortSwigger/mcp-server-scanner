package com.mcpscanner.access.comparison;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.mcpscanner.checks.api.ReplayPermission;
import com.mcpscanner.checks.api.crossidentity.IdentityIssue;
import com.mcpscanner.checks.api.crossidentity.IdentityObservation;
import com.mcpscanner.checks.api.crossidentity.OperationSeed;
import com.mcpscanner.checks.api.crossidentity.ReplayedOperation;

final class AccessIssues {

    private final ReplayPermission replays;

    AccessIssues(ReplayPermission replays) {
        this.replays = replays;
    }

    AuditIssue render(OperationSeed seed, Finding finding) {
        FindingKind kind = finding.kind();
        AuditIssueConfidence confidence = finding.confidence();
        IdentityObservation observation = new IdentityObservation(finding.principal(), finding.family(),
                finding.observation(), finding.evidence());
        return new IdentityIssue(kind.issueNameFor(finding.principal().role()), kind.severity(confidence), confidence, kind.background(),
                kind.strength(confidence), observation)
                .render(seed, ReplayedOperation.of(seed, replays), AccessIssueMetadata.CWES,
                        AccessIssueMetadata.REFERENCES);
    }
}
