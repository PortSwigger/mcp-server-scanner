package com.mcpscanner.checks.issue;

import java.util.List;

/**
 * Renders the Burp-whitelisted background HTML for an extension {@link burp.api.montoya.scanner.audit.issues.AuditIssue}.
 * Montoya offers no first-class References or Vulnerability-Classifications field for custom issues, so the
 * prose background, the CWE classifications, and the reference links are all folded into the {@code background}
 * argument of {@code AuditIssue.auditIssue(...)}.
 */
public final class IssueMetadataRenderer {

    private IssueMetadataRenderer() {}

    public static String background(IssueMetadata metadata) {
        return new IssueBodyBuilder()
                .paragraph(metadata.background())
                .vulnerabilityClassifications(metadata.cwes())
                .references(metadata.references())
                .build();
    }

    public static String background(String prose, List<Cwe> cwes, List<String> references) {
        return new IssueBodyBuilder()
                .paragraph(prose)
                .vulnerabilityClassifications(cwes)
                .references(references)
                .build();
    }
}
