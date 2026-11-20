package com.mcpscanner.access.listing;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.mcpscanner.checks.issue.Cwe;
import com.mcpscanner.checks.issue.IssueBodyBuilder;
import com.mcpscanner.checks.issue.IssueMetadataRenderer;

import java.util.List;

final class ListingIssues {

    private static final List<Cwe> CWES = List.of(new Cwe(287, "Improper Authentication"),
            new Cwe(269, "Improper Privilege Management"));
    private static final List<String> REFERENCES = List.of(
            "https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization",
            "https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices",
            "https://cwe.mitre.org/data/definitions/287.html",
            "https://cwe.mitre.org/data/definitions/269.html");

    private final ListingEvidence evidence;
    private final String endpoint;

    ListingIssues(ListingEvidence evidence, String endpoint) {
        this.evidence = evidence;
        this.endpoint = endpoint;
    }

    AuditIssue render(ListingFinding finding) {
        ListingIssueKind kind = finding.kind();
        return AuditIssue.auditIssue(kind.issueName(), detail(finding), kind.remediation(), endpoint,
                finding.severity(), finding.confidence(),
                IssueMetadataRenderer.background(kind.background(), CWES, REFERENCES), "", finding.severity(),
                evidence.of(finding).toArray(HttpRequestResponse[]::new));
    }

    private static String detail(ListingFinding finding) {
        return new IssueBodyBuilder()
                .paragraph(finding.kind().subject(finding, PrincipalLabels.names(finding.exceeded())))
                .paragraph(reachability(finding))
                .build();
    }

    private static String reachability(ListingFinding finding) {
        String principal = PrincipalLabels.label(finding.synthetic().principal());
        if (finding.confirmed()) {
            return "Check access called " + String.join(", ", confirmedTools(finding)) + " as " + principal
                    + " and the server returned a result with content, so these tools can be used, not only listed.";
        }
        return "No Check access call of these tools as " + principal + " returned a result with content, so the "
                + "listing is confirmed but not that the tools can be used.";
    }

    private static List<String> confirmedTools(ListingFinding finding) {
        return finding.confirmations().stream().map(call -> call.item().name()).toList();
    }
}
