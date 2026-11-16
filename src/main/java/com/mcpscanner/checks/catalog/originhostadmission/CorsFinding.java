package com.mcpscanner.checks.catalog.originhostadmission;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.List;

record CorsFinding(String scope, CorsAuth auth, boolean approvedWithCredentials, List<CorsEvidence> evidence) {

    CorsFinding {
        evidence = List.copyOf(evidence);
    }

    AuditIssueSeverity severity() {
        return CorsSeverity.of(auth, approvedWithCredentials);
    }

    String url() {
        return evidence.get(0).exchange().request().url();
    }
}
