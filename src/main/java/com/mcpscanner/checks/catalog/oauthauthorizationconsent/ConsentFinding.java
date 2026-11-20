package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;

import java.net.URI;
import java.util.List;

record ConsentFinding(ConsentIssueKind kind, AuditIssueConfidence confidence, URI location, List<String> facts,
                      List<HttpRequestResponse> evidence) {

    ConsentFinding {
        facts = List.copyOf(facts);
        evidence = List.copyOf(evidence);
    }

    ConsentFinding withEvidence(List<HttpRequestResponse> replaced) {
        return new ConsentFinding(kind, confidence, location, facts, replaced);
    }
}
