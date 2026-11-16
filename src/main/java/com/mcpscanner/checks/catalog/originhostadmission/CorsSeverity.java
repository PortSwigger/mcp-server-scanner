package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

final class CorsSeverity {

    private CorsSeverity() {
    }

    static AuditIssueSeverity of(CorsAuth auth, boolean approvedWithCredentials) {
        return switch (auth) {
            case NONE -> AuditIssueSeverity.HIGH;
            case COOKIE -> approvedWithCredentials ? AuditIssueSeverity.HIGH : AuditIssueSeverity.LOW;
            case HEADER -> AuditIssueSeverity.LOW;
        };
    }
}
