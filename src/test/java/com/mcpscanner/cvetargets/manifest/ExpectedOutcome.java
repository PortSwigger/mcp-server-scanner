package com.mcpscanner.cvetargets.manifest;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.List;

public record ExpectedOutcome(
        Outcome outcome,
        String issueName,
        AuditIssueSeverity severity,
        AuditIssueConfidence confidence,
        AuditIssueSeverity minimumSeverity,
        String knownMiss,
        String knownFlaky,
        List<String> alsoReports) {

    public ExpectedOutcome {
        alsoReports = alsoReports == null ? List.of() : List.copyOf(alsoReports);
    }

    public ExpectedOutcome(Outcome outcome, String issueName, AuditIssueSeverity severity,
                           AuditIssueConfidence confidence, AuditIssueSeverity minimumSeverity, String knownMiss,
                           String knownFlaky) {
        this(outcome, issueName, severity, confidence, minimumSeverity, knownMiss, knownFlaky, List.of());
    }

    public ExpectedOutcome(Outcome outcome, String issueName, AuditIssueSeverity severity,
                           AuditIssueConfidence confidence, AuditIssueSeverity minimumSeverity, String knownMiss) {
        this(outcome, issueName, severity, confidence, minimumSeverity, knownMiss, null);
    }

    public static ExpectedOutcome of(Outcome outcome) {
        return new ExpectedOutcome(outcome, null, null, null, null, null);
    }

    public ExpectedOutcome alsoReporting(List<String> declaredIssueNames) {
        return new ExpectedOutcome(outcome, issueName, severity, confidence, minimumSeverity, knownMiss, knownFlaky,
                declaredIssueNames);
    }

    public boolean isKnownMiss() {
        return knownMiss != null;
    }

    public boolean isKnownFlaky() {
        return knownFlaky != null;
    }

    public boolean declares(String reportedIssueName) {
        return alsoReports.contains(reportedIssueName);
    }
}
