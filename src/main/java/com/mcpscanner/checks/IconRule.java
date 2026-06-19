package com.mcpscanner.checks;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

public enum IconRule {
    UNSAFE_SCHEME(AuditIssueSeverity.HIGH, "unsafe scheme"),
    HTTP_SCHEME(AuditIssueSeverity.MEDIUM, "plaintext HTTP"),
    CROSS_ORIGIN(AuditIssueSeverity.LOW, "cross-origin"),
    SVG_MIME(AuditIssueSeverity.INFORMATION, "SVG MIME type"),
    OVERSIZED(AuditIssueSeverity.LOW, "oversized");

    private final AuditIssueSeverity severity;
    private final String label;

    IconRule(AuditIssueSeverity severity, String label) {
        this.severity = severity;
        this.label = label;
    }

    public AuditIssueSeverity severity() {
        return severity;
    }

    public String label() {
        return label;
    }
}
