package com.mcpscanner.checks.content;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.Objects;

public record ContentFinding(ContentRule rule, ContentRuleContext context, Violation violation) {

    public ContentFinding {
        Objects.requireNonNull(rule, "rule must not be null");
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(violation, "violation must not be null");
    }

    public InspectedField field() {
        return violation.field();
    }

    public String matchedText() {
        return violation.matchedText();
    }

    public AuditIssueSeverity severity() {
        return violation.severity();
    }
}
