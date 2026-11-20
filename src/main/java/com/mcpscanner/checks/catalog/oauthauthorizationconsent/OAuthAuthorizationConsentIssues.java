package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;

import java.util.List;

final class OAuthAuthorizationConsentIssues {

    private final CheckDescriptor descriptor;

    OAuthAuthorizationConsentIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    List<AuditIssue> issues(List<ConsentFinding> findings) {
        return findings.stream().map(this::issue).toList();
    }

    private AuditIssue issue(ConsentFinding finding) {
        ConsentIssueKind kind = finding.kind();
        return AuditIssue.auditIssue(
                kind.issueName(),
                detail(finding),
                kind.remediation(),
                finding.location().toString(),
                kind.severity(),
                finding.confidence(),
                IssueMetadataRenderer.background(descriptor.issueBackground(), descriptor.cwes(),
                        descriptor.references()),
                null,
                kind.severity(),
                finding.evidence());
    }

    private static String detail(ConsentFinding finding) {
        IssueBodyBuilder body = new IssueBodyBuilder().paragraph(finding.kind().observation())
                .findings(finding.facts());
        finding.kind().limits().ifPresent(body::paragraph);
        return body.build();
    }
}
