package com.mcpscanner.checks.content;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

public record Violation(ContentRule rule, InspectedField field, String matchedText, AuditIssueSeverity severity) {

    public Violation(ContentRule rule, InspectedField field, String matchedText) {
        this(rule, field, matchedText, rule.severity());
    }
}
