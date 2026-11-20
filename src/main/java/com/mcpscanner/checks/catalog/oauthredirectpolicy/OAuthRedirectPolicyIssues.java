package com.mcpscanner.checks.catalog.oauthredirectpolicy;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

final class OAuthRedirectPolicyIssues {

    private final CheckDescriptor descriptor;

    OAuthRedirectPolicyIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    List<AuditIssue> issues(List<RedirectFinding> findings) {
        Map<FindingKind, List<RedirectFinding>> byKind = new EnumMap<>(FindingKind.class);
        findings.forEach(finding -> byKind.computeIfAbsent(finding.kind(), kind -> new ArrayList<>()).add(finding));
        return byKind.entrySet().stream().map(entry -> issue(entry.getKey(), entry.getValue())).toList();
    }

    private AuditIssue issue(FindingKind kind, List<RedirectFinding> findings) {
        return AuditIssue.auditIssue(
                kind.issueName(),
                detail(kind, findings),
                kind.remediation(),
                findings.get(0).location().toString(),
                kind.severity(),
                kind.confidence(),
                IssueMetadataRenderer.background(descriptor.issueBackground(), descriptor.cwes(),
                        descriptor.references()),
                null,
                kind.severity(),
                evidence(findings));
    }

    private static String detail(FindingKind kind, List<RedirectFinding> findings) {
        IssueBodyBuilder body = new IssueBodyBuilder()
                .paragraph(kind.observation())
                .findings(findings.stream().map(RedirectFinding::summary).toList());
        if (findings.size() > 1) {
            body.paragraph("The attached exchanges show only the first case listed: " + findings.get(0).summary()
                    + ".");
        }
        return body.paragraph(kind.limits()).build();
    }

    private static List<HttpRequestResponse> evidence(List<RedirectFinding> findings) {
        return findings.get(0).evidence();
    }
}
