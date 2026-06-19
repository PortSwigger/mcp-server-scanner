package com.mcpscanner.checks.content;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.mcpscanner.checks.issue.IssueMetadata;

import java.util.List;

public interface ContentRule {

    String id();

    String displayName();

    AuditIssueSeverity severity();

    default AuditIssueConfidence confidence() {
        return AuditIssueConfidence.FIRM;
    }

    List<Violation> evaluate(InspectedField field);

    default List<Violation> evaluateContent(DiscoveredContent content, HttpService host) {
        return List.of();
    }

    IssueMetadata metadata();
}
