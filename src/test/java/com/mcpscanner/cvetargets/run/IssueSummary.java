package com.mcpscanner.cvetargets.run;

import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.automation.EvidenceSummary;

import java.util.List;

public record IssueSummary(String name, AuditIssueSeverity severity, AuditIssueConfidence confidence, String baseUrl,
                           String detail, List<String> evidence) {

    public IssueSummary {
        evidence = evidence == null ? List.of() : List.copyOf(evidence);
    }

    public IssueSummary(String name, AuditIssueSeverity severity, AuditIssueConfidence confidence, String baseUrl,
                        String detail) {
        this(name, severity, confidence, baseUrl, detail, List.of());
    }

    public static IssueSummary of(AuditIssue issue) {
        return new IssueSummary(issue.name(), issue.severity(), issue.confidence(), issue.baseUrl(), issue.detail(),
                EvidenceSummary.of(issue.requestResponses()));
    }
}
