package com.mcpscanner.checks.catalog.siblingrouteauthparity;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.api.CheckDescriptor;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;
import com.mcpscanner.checks.issue.IssueRating;
import com.mcpscanner.checks.shared.jsonrpc.JsonRpcEnvelope;

final class SiblingRouteAuthParityIssues {

    private final CheckDescriptor descriptor;

    SiblingRouteAuthParityIssues(CheckDescriptor descriptor) {
        this.descriptor = descriptor;
    }

    AuditIssue render(Finding finding) {
        FindingKind kind = finding.route().kind();
        IssueRating rating = kind.rating();
        return AuditIssue.auditIssue(kind.issueName(), detail(kind, finding), kind.remediation(),
                finding.baseline().request().url(), rating.severity(), rating.confidence(),
                IssueMetadataRenderer.background(kind.background(), descriptor.cwes(), descriptor.references()),
                "", rating.severity(), finding.evidence().toArray(HttpRequestResponse[]::new));
    }

    private static String detail(FindingKind kind, Finding finding) {
        String method = JsonRpcEnvelope.of(finding.baseline().request()).method().orElse("");
        return new IssueBodyBuilder()
                .paragraph(kind.lead(finding.baseline().request().pathWithoutQuery(),
                        finding.route().variant().candidate().value()))
                .paragraph("JSON-RPC method: " + method + ". The unauthenticated response listed the same items "
                        + "as the authenticated request, which is the first request in the evidence; the anonymous "
                        + "request to the main route was refused before and after it: the second request in the "
                        + "evidence is that refusal, and the repeat after it is not attached. Only the catalog listing "
                        + "was tested.")
                .build();
    }
}
