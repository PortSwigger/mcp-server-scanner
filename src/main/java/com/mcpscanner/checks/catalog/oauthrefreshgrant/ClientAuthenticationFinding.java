package com.mcpscanner.checks.catalog.oauthrefreshgrant;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import com.mcpscanner.auth.grant.ClientType;

import java.util.List;

record ClientAuthenticationFinding(ClientType clientType, boolean confidentialityEstablished,
                                   List<JudgedRefresh> accepted, RefreshEvidence evidence) {

    ClientAuthenticationFinding {
        accepted = List.copyOf(accepted);
    }

    AuditIssueConfidence confidence() {
        boolean allUsable = accepted.stream().allMatch(refresh -> refresh.usability() == Usability.USABLE);
        return confidentialityEstablished && allUsable ? AuditIssueConfidence.FIRM : AuditIssueConfidence.TENTATIVE;
    }

    JudgedRefresh strongestAccepted() {
        return accepted.stream()
                .filter(refresh -> refresh.usability() == Usability.USABLE)
                .findFirst()
                .orElse(accepted.get(0));
    }
}
