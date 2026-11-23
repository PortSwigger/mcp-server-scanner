package com.mcpscanner.checks.catalog.oauthauthorizationconsent;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.Optional;

interface ConsentIssueKind {

    String issueName();

    AuditIssueSeverity severity();

    String observation();

    String remediation();

    Optional<String> limits();
}
