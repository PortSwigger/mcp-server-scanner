package com.mcpscanner.checks.registry;

import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

public record ContentRuleDescriptor(String id, String displayName, AuditIssueSeverity severity) {

    public static final String MASTER_ID = "discovery-content-scanner";
    public static final String RESPONSE_CONTENT_ID = "response-content-scanner";
}
