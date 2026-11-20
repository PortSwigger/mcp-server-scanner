package com.mcpscanner.access;

import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.List;

public interface ListingAudit {

    ListingAudit NONE = List::of;

    List<AuditIssue> issues();
}
