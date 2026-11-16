package com.mcpscanner.checks.catalog.sqlinjection;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;

import java.util.List;
import java.util.Objects;

record Finding(ValueSlot slot, List<SyntaxForm> forms, AuditIssueConfidence confidence,
               List<HttpRequestResponse> evidence) {

    Finding {
        forms = List.copyOf(forms);
        evidence = evidence.stream().filter(Objects::nonNull).toList();
    }
}
